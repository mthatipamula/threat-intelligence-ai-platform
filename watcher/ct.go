package main

// Certificate Transparency client: the read API every CT log serves (RFC 6962, section 4).
//
//   GET <log>/ct/v1/get-sth                       -> current tree size (how many certificates are in the log)
//   GET <log>/ct/v1/get-entries?start=N&end=M     -> entries N..M (logs return at most a few dozen per call)
//
// Each entry is a MerkleTreeLeaf. For an ordinary certificate the leaf holds the certificate itself; for a
// precertificate (issued before the final certificate, so it can be logged first) the leaf holds only the
// to-be-signed part, and the full precertificate is the first item in extra_data. Both parse with crypto/x509.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	entryX509    = 0
	entryPrecert = 1
)

type logClient struct {
	name string
	url  string
	http *http.Client
	// When the log rate-limits one worker, every worker on that log waits until this time (unix nanoseconds),
	// rather than each one retrying on its own and getting limited for longer.
	pauseUntil  atomic.Int64
	rateLimited atomic.Uint64
}

// errRateLimited marks a 429 that outlasted the retries; callers back off and try again rather than skip entries.
var errRateLimited = errors.New("rate limited")

type sth struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp int64  `json:"timestamp"`
}

type rawEntry struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

// Cert is what the watcher keeps from each log entry.
type Cert struct {
	Log       string
	Index     uint64
	Names     []string // subject CN and DNS SANs, lower-case
	Issuer    string
	NotBefore time.Time
	Precert   bool
}

func newLogClient(url string) *logClient {
	url = strings.TrimRight(url, "/")
	name := url[strings.LastIndex(url, "/")+1:]
	return &logClient{name: name, url: url, http: &http.Client{Timeout: 20 * time.Second}}
}

// waitForPause blocks while the log has asked us to slow down.
func (c *logClient) waitForPause(ctx context.Context) error {
	for {
		wait := time.Until(time.Unix(0, c.pauseUntil.Load()))
		if wait <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// pause asks every worker on this log to wait: for Retry-After if the log sent one, else for the backoff.
func (c *logClient) pause(retryAfter string, fallback time.Duration) {
	d := fallback
	if secs, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && secs > 0 {
		d = min(time.Duration(secs)*time.Second, time.Minute)
	}
	until := time.Now().Add(d).UnixNano()
	for {
		cur := c.pauseUntil.Load()
		if cur >= until || c.pauseUntil.CompareAndSwap(cur, until) {
			return
		}
	}
}

// getJSON fetches with retries: logs rate-limit (429, honouring Retry-After) and occasionally fail (5xx).
func (c *logClient) getJSON(ctx context.Context, path string, into any) error {
	backoff := 500 * time.Millisecond
	for attempt := 0; ; attempt++ {
		if err := c.waitForPause(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "threat-intelligence-ai-platform-ct-watcher/0.1")
		resp, err := c.http.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK {
				return json.Unmarshal(body, into)
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				c.rateLimited.Add(1)
				c.pause(resp.Header.Get("Retry-After"), backoff)
				err = errRateLimited
			} else {
				err = fmt.Errorf("%s%s: HTTP %d", c.name, path, resp.StatusCode)
				if resp.StatusCode < 500 {
					return err // not worth retrying
				}
			}
		}
		if attempt == 4 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff = min(backoff*2, 30*time.Second)
		}
	}
}

func (c *logClient) treeSize(ctx context.Context) (uint64, error) {
	var s sth
	if err := c.getJSON(ctx, "/ct/v1/get-sth", &s); err != nil {
		return 0, err
	}
	return s.TreeSize, nil
}

// entries fetches [start, end]. The log may return fewer than asked; the caller continues from what it got.
func (c *logClient) entries(ctx context.Context, start, end uint64) ([]Cert, int, error) {
	var resp struct {
		Entries []rawEntry `json:"entries"`
	}
	if err := c.getJSON(ctx, fmt.Sprintf("/ct/v1/get-entries?start=%d&end=%d", start, end), &resp); err != nil {
		return nil, 0, err
	}
	certs := make([]Cert, 0, len(resp.Entries))
	for i, e := range resp.Entries {
		cert, err := parseEntry(e)
		if err != nil {
			continue // a malformed or unusual entry shouldn't stop the stream
		}
		cert.Log, cert.Index = c.name, start+uint64(i)
		certs = append(certs, cert)
	}
	return certs, len(resp.Entries), nil
}

// readCert reads a TLS-style opaque ASN.1Cert: a 3-byte big-endian length followed by DER.
func readCert(b []byte) ([]byte, error) {
	if len(b) < 3 {
		return nil, errors.New("short certificate field")
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	if len(b) < 3+n {
		return nil, errors.New("truncated certificate")
	}
	return b[3 : 3+n], nil
}

func parseEntry(e rawEntry) (Cert, error) {
	leaf, err := base64.StdEncoding.DecodeString(e.LeafInput)
	if err != nil || len(leaf) < 12 {
		return Cert{}, errors.New("bad leaf")
	}
	// version(1) leaf_type(1) timestamp(8) entry_type(2)
	entryType := binary.BigEndian.Uint16(leaf[10:12])
	var der []byte
	switch entryType {
	case entryX509:
		der, err = readCert(leaf[12:])
	case entryPrecert:
		extra, decErr := base64.StdEncoding.DecodeString(e.ExtraData)
		if decErr != nil {
			return Cert{}, decErr
		}
		der, err = readCert(extra) // PrecertChainEntry starts with the full precertificate
	default:
		return Cert{}, fmt.Errorf("unknown entry type %d", entryType)
	}
	if err != nil {
		return Cert{}, err
	}
	// Precertificates carry a critical "poison" extension; ParseCertificate tolerates it (only verification fails).
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return Cert{}, err
	}
	names := make([]string, 0, len(x.DNSNames)+1)
	if x.Subject.CommonName != "" {
		names = append(names, strings.ToLower(x.Subject.CommonName))
	}
	for _, n := range x.DNSNames {
		names = append(names, strings.ToLower(n))
	}
	issuer := x.Issuer.CommonName
	if len(x.Issuer.Organization) > 0 {
		issuer = x.Issuer.Organization[0] + " " + issuer
	}
	return Cert{Names: names, Issuer: issuer, NotBefore: x.NotBefore, Precert: entryType == entryPrecert}, nil
}
