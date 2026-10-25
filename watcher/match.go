package main

// Lookalike matching: does a certificate name imitate one of the watched brand domains?
//
// Three checks, cheapest first:
//   1. exact match against generated candidates (dropped/doubled/swapped letters, look-alike characters, Cyrillic
//      homoglyphs, brand+keyword, other TLDs) - the same techniques as the Python collector, so both agree;
//   2. the brand word inside another registrable domain (coinbase-verify.app, login.coinbase.secure-help.com);
//   3. a near-miss spelling of the brand label within one edit (catches typos the generator didn't list).
// The brand's own domain and its subdomains are never hits.

import (
	"strings"

	"golang.org/x/net/idna"
)

var (
	homoglyphs = map[rune][]string{'o': {"0"}, 'l': {"1", "i"}, 'i': {"1", "l"}, 'm': {"rn"}, 'w': {"vv"}, 'e': {"3"}, 'a': {"4"}, 's': {"5"}}
	cyrillic   = map[rune]rune{'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'x': 'х', 'y': 'у'}
	keywords   = []string{"login", "signin", "secure", "verify", "support", "help", "wallet", "app", "careers", "jobs", "recovery", "kyc"}
	tlds       = []string{"com", "net", "org", "io", "co", "app", "xyz", "info", "online", "site", "us", "pro"}
	// second-level suffixes where the registrable domain is three labels (example.co.uk)
	twoPartSuffixes = map[string]bool{"co.uk": true, "org.uk": true, "com.au": true, "com.br": true, "co.jp": true,
		"co.in": true, "com.cn": true, "com.mx": true, "co.za": true, "com.sg": true, "com.tr": true}
)

type brand struct {
	domain     string
	label      string
	candidates map[string]string // lookalike domain -> technique
}

// Hit is one certificate name that imitates a brand.
type Hit struct {
	Domain    string `json:"domain"`     // registrable domain, e.g. coinbase-verify.app
	Name      string `json:"name"`       // the exact name in the certificate, e.g. login.coinbase-verify.app
	Brand     string `json:"brand"`      // the watched domain it imitates
	Technique string `json:"technique"`  // how: omission, homoglyph, keyword, brand-in-domain, edit-distance...
	Log       string `json:"log"`        // which CT log
	Index     uint64 `json:"index"`      // entry index in that log
	Issuer    string `json:"issuer"`     // certificate authority
	NotBefore string `json:"not_before"` // when the certificate became valid
	Precert   bool   `json:"precert"`
	SeenAt    string `json:"seen_at"` // when the watcher saw it
}

func newBrand(domain string) brand {
	domain = strings.ToLower(strings.TrimSpace(domain))
	label, tld, _ := strings.Cut(domain, ".")
	b := brand{domain: domain, label: label, candidates: map[string]string{}}
	add := func(l, technique, suffix string) {
		c := l + "." + suffix
		if l != "" && c != domain {
			if _, seen := b.candidates[c]; !seen {
				b.candidates[c] = technique
			}
		}
	}
	r := []rune(label)
	for i := range r {
		add(string(r[:i])+string(r[i+1:]), "omission", tld)
		add(string(r[:i+1])+string(r[i:]), "repetition", tld)
		if i < len(r)-1 {
			s := append([]rune{}, r...)
			s[i], s[i+1] = s[i+1], s[i]
			add(string(s), "transposition", tld)
		}
		for _, g := range homoglyphs[r[i]] {
			add(string(r[:i])+g+string(r[i+1:]), "homoglyph", tld)
		}
		if cy, ok := cyrillic[r[i]]; ok {
			if ascii, err := idna.ToASCII(string(r[:i]) + string(cy) + string(r[i+1:])); err == nil {
				add(ascii, "idn-homoglyph", tld)
			}
		}
	}
	for _, k := range keywords {
		add(label+"-"+k, "keyword", tld)
		add(k+"-"+label, "keyword", tld)
		add(label+k, "keyword", tld)
	}
	for _, t := range tlds {
		if t != tld {
			add(label, "tld-swap", t)
		}
	}
	return b
}

// registrable approximates the registered domain: the last two labels, or three for suffixes like co.uk.
func registrable(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}
	n := 2
	if len(parts) >= 3 && twoPartSuffixes[strings.Join(parts[len(parts)-2:], ".")] {
		n = 3
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

// withinOneEdit reports whether a and b differ by one insertion, deletion, substitution or adjacent swap.
func withinOneEdit(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	if la == lb {
		diff := []int{}
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				diff = append(diff, i)
			}
		}
		return len(diff) == 1 || (len(diff) == 2 && diff[1] == diff[0]+1 && a[diff[0]] == b[diff[1]] && a[diff[1]] == b[diff[0]])
	}
	if la < lb {
		a, b = b, a
	}
	for i := 0; i < len(b); i++ {
		if a[i] != b[i] {
			return a[i+1:] == b[i:]
		}
	}
	return true
}

type matcher struct{ brands []brand }

func newMatcher(domains []string) *matcher {
	m := &matcher{}
	for _, d := range domains {
		if strings.TrimSpace(d) != "" {
			m.brands = append(m.brands, newBrand(d))
		}
	}
	return m
}

// check returns at most one hit per (brand, registrable domain) for a certificate name.
func (m *matcher) check(name string) (Hit, bool) {
	name = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(name), "."), "*.")
	if name == "" || !strings.Contains(name, ".") {
		return Hit{}, false
	}
	reg := registrable(name)
	regLabel, _, _ := strings.Cut(reg, ".")
	for _, b := range m.brands {
		if reg == b.domain || strings.HasSuffix(name, "."+b.domain) {
			continue // the brand's own domain
		}
		if technique, ok := b.candidates[reg]; ok {
			return Hit{Domain: reg, Name: name, Brand: b.domain, Technique: technique}, true
		}
		// the brand word anywhere, also when split by hyphens (coin-base-help.com)
		if len(b.label) >= 5 && strings.Contains(strings.ReplaceAll(name, "-", ""), b.label) {
			return Hit{Domain: reg, Name: name, Brand: b.domain, Technique: "brand-in-domain"}, true
		}
		if len(b.label) >= 6 && withinOneEdit(regLabel, b.label) {
			return Hit{Domain: reg, Name: name, Brand: b.domain, Technique: "edit-distance"}, true
		}
	}
	return Hit{}, false
}
