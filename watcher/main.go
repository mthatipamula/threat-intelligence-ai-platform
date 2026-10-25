// ct-watcher: streams Certificate Transparency logs and reports certificates for domains imitating watched brands.
//
// Every publicly trusted TLS certificate must be published in CT logs, usually before a site goes live, so a
// lookalike phishing domain (c0inbase-login.app) shows up here hours or days before the first phishing email.
//
// Design: for each log, a dispatcher hands out index ranges near the head of the log to a pool of worker goroutines;
// workers fetch and parse entries concurrently and send matches to one output goroutine, which de-duplicates them and
// writes JSON lines and/or posts batches to the platform's API (POST /api/intel/ct-hits), which stores them as STIX
// indicators. A replay mode reads certificate names from a file, for demos without network access.
//
//	go run . -brands coinbase.com -duration 2m -post http://localhost:8000/api/intel/ct-hits
//	go run . -brands coinbase.com -replay testdata/names.txt
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var defaultLogs = []string{
	"https://ct.googleapis.com/logs/us1/argon2026h2/",
	"https://ct.googleapis.com/logs/eu1/xenon2026h2/",
	"https://ct.cloudflare.com/logs/nimbus2026/",
}

type config struct {
	brands     []string
	logs       []string
	workers    int
	batch      uint64
	backlog    uint64
	duration   time.Duration
	maxEntries uint64
	out        string
	post       string
	replay     string
}

func parseFlags() config {
	var c config
	brands := flag.String("brands", "coinbase.com", "comma-separated brand domains to protect")
	logs := flag.String("logs", strings.Join(defaultLogs, ","), "comma-separated CT log URLs (RFC 6962)")
	flag.IntVar(&c.workers, "workers", 4, "concurrent fetchers per log (be polite: logs rate-limit)")
	batch := flag.Uint("batch", 32, "entries requested per get-entries call (logs cap this)")
	backlog := flag.Uint("backlog", 2000, "start this many entries behind the head of each log")
	flag.DurationVar(&c.duration, "duration", 0, "stop after this long (0 = run until interrupted)")
	maxEntries := flag.Uint("max-entries", 0, "stop each log after this many entries (0 = no limit)")
	flag.StringVar(&c.out, "out", "", "append hits as JSON lines to this file")
	flag.StringVar(&c.post, "post", "", "POST batches of hits to this URL (the platform API)")
	flag.StringVar(&c.replay, "replay", "", "read certificate names from this file instead of CT logs")
	flag.Parse()
	c.brands, c.logs = splitList(*brands), splitList(*logs)
	c.batch, c.backlog, c.maxEntries = uint64(*batch), uint64(*backlog), uint64(*maxEntries)
	return c
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	cfg := parseFlags()
	if len(cfg.brands) == 0 {
		log.Fatal("no brands to watch")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.duration)
		defer cancel()
	}

	m := newMatcher(cfg.brands)
	hits := make(chan Hit, 256)
	sink := newSink(cfg)
	var sinkDone sync.WaitGroup
	sinkDone.Add(1)
	go func() { defer sinkDone.Done(); sink.run(ctx, hits) }()

	if cfg.replay != "" {
		replay(cfg.replay, m, hits)
	} else {
		stream(ctx, cfg, m, hits)
	}
	close(hits)
	sinkDone.Wait()
	log.Printf("done: %d unique lookalike domains reported", sink.reported)
}

// replay matches certificate names read from a file (one per line), for demos and offline runs.
func replay(path string, m *matcher, hits chan<- Hit) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	n := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		if h, ok := m.check(line); ok {
			h.Log, h.Index, h.SeenAt = "replay:"+path, uint64(n), time.Now().UTC().Format(time.RFC3339)
			hits <- h
		}
	}
	log.Printf("replayed %d names from %s", n, path)
}

type logStats struct {
	name      string
	processed atomic.Uint64
	certs     atomic.Uint64
	next      atomic.Uint64
	head      atomic.Uint64
	errors    atomic.Uint64
	client    *logClient
}

// stream follows every configured log concurrently until the context ends or each log hits max-entries.
func stream(ctx context.Context, cfg config, m *matcher, hits chan<- Hit) {
	var wg sync.WaitGroup
	stats := make([]*logStats, 0, len(cfg.logs))
	for _, url := range cfg.logs {
		client := newLogClient(url)
		st := &logStats{name: client.name, client: client}
		stats = append(stats, st)
		wg.Add(1)
		go func() { defer wg.Done(); followLog(ctx, cfg, client, m, hits, st) }()
	}
	reportDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		last := map[string]uint64{}
		for {
			select {
			case <-reportDone:
				return
			case <-ticker.C:
				for _, s := range stats {
					p := s.processed.Load()
					lag := int64(s.head.Load()) - int64(s.next.Load())
					log.Printf("%-16s %6.0f entries/s  %d certs parsed  %d behind head  %d rate-limited  %d errors",
						s.name, float64(p-last[s.name])/10, s.certs.Load(), max(lag, 0), s.client.rateLimited.Load(),
						s.errors.Load())
					last[s.name] = p
				}
			}
		}
	}()
	wg.Wait()
	close(reportDone)
}

func followLog(ctx context.Context, cfg config, c *logClient, m *matcher, hits chan<- Hit, st *logStats) {
	size, err := c.treeSize(ctx)
	if err != nil {
		log.Printf("%s: cannot read tree size: %v", c.name, err)
		return
	}
	start := uint64(0)
	if size > cfg.backlog {
		start = size - cfg.backlog
	}
	st.head.Store(size)
	st.next.Store(start)
	log.Printf("%s: %d certificates in log, starting at %d", c.name, size, start)

	ranges := make(chan [2]uint64)
	var workers sync.WaitGroup
	for range cfg.workers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for r := range ranges {
				fetchRange(ctx, c, r[0], r[1], m, hits, st)
			}
		}()
	}

	limit := uint64(0)
	if cfg.maxEntries > 0 {
		limit = start + cfg.maxEntries
	}
	next := start
dispatch:
	for {
		if ctx.Err() != nil || (limit > 0 && next >= limit) {
			break
		}
		head := st.head.Load()
		if next >= head { // caught up: wait, then see how far the log has grown
			select {
			case <-ctx.Done():
				break dispatch
			case <-time.After(5 * time.Second):
			}
			if s, err := c.treeSize(ctx); err == nil {
				st.head.Store(s)
			}
			continue
		}
		end := min(next+cfg.batch, head)
		if limit > 0 {
			end = min(end, limit)
		}
		select {
		case ranges <- [2]uint64{next, end - 1}:
			next = end
			st.next.Store(next)
		case <-ctx.Done():
			break dispatch
		}
	}
	close(ranges)
	workers.Wait()
}

// fetchRange gets [start, end]. Logs may return fewer entries than asked, so it continues until the range is done;
// on failure it backs off and retries rather than skipping certificates (a gap could hide the one that matters).
func fetchRange(ctx context.Context, c *logClient, start, end uint64, m *matcher, hits chan<- Hit, st *logStats) {
	backoff := 2 * time.Second
	for start <= end && ctx.Err() == nil {
		certs, n, err := c.entries(ctx, start, end)
		if err != nil || n == 0 {
			if ctx.Err() != nil {
				return
			}
			if !errors.Is(err, errRateLimited) {
				st.errors.Add(1)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, time.Minute)
			}
			continue
		}
		backoff = 2 * time.Second
		st.processed.Add(uint64(n))
		st.certs.Add(uint64(len(certs)))
		now := time.Now().UTC().Format(time.RFC3339)
		for _, cert := range certs {
			for _, name := range cert.Names {
				if h, ok := m.check(name); ok {
					h.Log, h.Index, h.Issuer, h.Precert, h.SeenAt = cert.Log, cert.Index, cert.Issuer, cert.Precert, now
					h.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
					hits <- h
					break // one hit per certificate is enough
				}
			}
		}
		start += uint64(n)
	}
}

// sink de-duplicates hits per (brand, domain) and writes them out: stdout, a JSON-lines file, and/or the API.
type sink struct {
	cfg      config
	seen     map[string]bool
	pending  []Hit
	file     *os.File
	reported int
}

func newSink(cfg config) *sink {
	s := &sink{cfg: cfg, seen: map[string]bool{}}
	if cfg.out != "" {
		f, err := os.OpenFile(cfg.out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		s.file = f
	}
	return s
}

func (s *sink) run(ctx context.Context, hits <-chan Hit) {
	flush := time.NewTicker(5 * time.Second)
	defer flush.Stop()
	defer s.flush()
	if s.file != nil {
		defer s.file.Close()
	}
	for {
		select {
		case h, ok := <-hits:
			if !ok {
				return
			}
			key := h.Brand + "|" + h.Domain
			if s.seen[key] {
				continue
			}
			s.seen[key] = true
			s.reported++
			line, _ := json.Marshal(h)
			fmt.Println(string(line))
			if s.file != nil {
				s.file.Write(append(line, '\n'))
			}
			s.pending = append(s.pending, h)
			if len(s.pending) >= 50 {
				s.flush()
			}
		case <-flush.C:
			s.flush()
		}
	}
}

func (s *sink) flush() {
	if s.cfg.post == "" || len(s.pending) == 0 {
		s.pending = s.pending[:0]
		return
	}
	body, _ := json.Marshal(map[string]any{"hits": s.pending})
	resp, err := http.Post(s.cfg.post, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("post failed (%d hits kept for retry): %v", len(s.pending), err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("post failed with HTTP %d (%d hits kept for retry)", resp.StatusCode, len(s.pending))
		return
	}
	log.Printf("posted %d hits", len(s.pending))
	s.pending = s.pending[:0]
}
