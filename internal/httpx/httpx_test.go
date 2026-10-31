package httpx

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"
)

func TestBrowserNavigationHeaders(t *testing.T) {
	h := http.Header{}
	SetBrowserNavigation(h, "https://example.com/")

	for k, want := range map[string]string{
		"User-Agent":                BrowserUserAgent,
		"Accept-Language":           "en-US,en;q=0.9",
		"Sec-CH-UA-Mobile":          "?0",
		"Sec-CH-UA-Platform":        `"macOS"`,
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-User":            "?1",
		"Sec-Fetch-Dest":            "document",
		"Upgrade-Insecure-Requests": "1",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if got := h.Get("Accept"); !strings.Contains(got, "text/html") {
		t.Errorf("Accept = %q, want a navigation Accept", got)
	}
	if got := h.Get("Sec-CH-UA"); !strings.Contains(got, `"Google Chrome";v="156"`) {
		t.Errorf("Sec-CH-UA = %q, want Chrome 156", got)
	}
	if strings.Contains(strings.ToLower(h.Get("User-Agent")), "norma") {
		t.Error("User-Agent still identifies the SDK")
	}
}

func TestBrowserFormNavigationHeaders(t *testing.T) {
	h := http.Header{}
	SetBrowserFormNavigation(h, "https://example.com/search/")

	if got := h.Get("Origin"); got != "https://example.com" {
		t.Errorf("Origin = %q, want scheme://host", got)
	}
	if got := h.Get("Referer"); got != "https://example.com/search/" {
		t.Errorf("Referer = %q, want the form's page", got)
	}
	if got := h.Get("Sec-Fetch-Site"); got != "same-origin" {
		t.Errorf("Sec-Fetch-Site = %q, want same-origin", got)
	}
}

func TestBrowserSecureContextHeaders(t *testing.T) {
	h := http.Header{}
	SetBrowserNavigation(h, "http://example.com/")
	for _, k := range []string{
		"Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
	} {
		if got := h.Get(k); got != "" {
			t.Errorf("%s = %q, want absent on plain HTTP outside loopback", k, got)
		}
	}
	if got := h.Get("User-Agent"); got != BrowserUserAgent {
		t.Errorf("User-Agent = %q, want %q", got, BrowserUserAgent)
	}
	if got := h.Get("Upgrade-Insecure-Requests"); got != "1" {
		t.Errorf("Upgrade-Insecure-Requests = %q, want 1 on plain HTTP", got)
	}

	// Loopback HTTP counts as a secure context, so the full profile is sent.
	for _, target := range []string{"http://localhost:8080/", "http://127.0.0.1:8080/", "http://[::1]:8080/"} {
		loop := http.Header{}
		SetBrowserNavigation(loop, target)
		if got := loop.Get("Sec-CH-UA"); got != browserCHUA {
			t.Errorf("Sec-CH-UA for %s = %q, want %q", target, got, browserCHUA)
		}
		if got := loop.Get("Sec-Fetch-Site"); got != "none" {
			t.Errorf("Sec-Fetch-Site for %s = %q, want none", target, got)
		}
	}

	// HTTP -> HTTPS adds the secure-context headers; HTTPS -> HTTP removes them.
	plain, _ := url.Parse("http://example.com/")
	secure, _ := url.Parse("https://example.com/")
	req := &http.Request{URL: secure, Header: http.Header{}}
	if err := BrowserCheckRedirect(req, []*http.Request{{URL: plain, Header: http.Header{}}}); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"Sec-CH-UA":      browserCHUA,
		"Sec-Fetch-Site": "none",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
	} {
		if got := req.Header.Get(k); got != want {
			t.Errorf("%s after upgrade = %q, want %q", k, got, want)
		}
	}

	req = &http.Request{URL: plain, Header: http.Header{}}
	req.Header.Set("Sec-CH-UA", browserCHUA)
	req.Header.Set("Sec-Fetch-Site", "none")
	if err := BrowserCheckRedirect(req, []*http.Request{{URL: secure, Header: http.Header{}}}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"Sec-CH-UA", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest"} {
		if got := req.Header.Get(k); got != "" {
			t.Errorf("%s after downgrade = %q, want absent", k, got)
		}
	}
}

func TestBrowserFormNavigationPlainHTTPOmitsSecureHeaders(t *testing.T) {
	h := http.Header{}
	SetBrowserFormNavigation(h, "http://example.com/search/")
	for _, k := range []string{"Sec-CH-UA", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest"} {
		if got := h.Get(k); got != "" {
			t.Errorf("%s = %q, want absent on plain HTTP outside loopback", k, got)
		}
	}
	if got := h.Get("Origin"); got != "http://example.com" {
		t.Errorf("Origin = %q, want http://example.com", got)
	}
	if got := h.Get("Upgrade-Insecure-Requests"); got != "1" {
		t.Errorf("Upgrade-Insecure-Requests = %q, want 1", got)
	}
}

func TestSDKHeaders(t *testing.T) {
	cases := map[string]struct {
		set     func(http.Header)
		ua      string
		version string
	}{
		"anthropic": {SetAnthropicSDK, "Anthropic/Go " + AnthropicSDKVersion, AnthropicSDKVersion},
		"openai":    {SetOpenAISDK, "OpenAI/Go " + OpenAISDKVersion, OpenAISDKVersion},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := http.Header{}
			tc.set(h)
			if got := h.Get("User-Agent"); got != tc.ua {
				t.Errorf("User-Agent = %q, want %q", got, tc.ua)
			}
			for k, want := range map[string]string{
				"X-Stainless-Lang":            "go",
				"X-Stainless-Package-Version": tc.version,
				"X-Stainless-OS":              sdkOS(),
				"X-Stainless-Arch":            sdkArch(),
				"X-Stainless-Runtime":         "go",
				"X-Stainless-Runtime-Version": runtime.Version(),
				"X-Stainless-Retry-Count":     "0",
			} {
				if got := h.Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			if got := h.Get("Accept"); got != "application/json" {
				t.Errorf("Accept = %q, want application/json even for streaming", got)
			}
			if got := h.Get("X-Stainless-Timeout"); got != "" {
				t.Errorf("X-Stainless-Timeout = %q, want absent without a request timeout", got)
			}
		})
	}
}

func TestBrowserRedirectReferrerPolicy(t *testing.T) {
	cases := []struct {
		name        string
		prev, next  string
		wantReferer string
		wantSite    string
	}{
		{"same origin keeps the full URL", "https://example.com/a/b?q=1#frag", "https://example.com/c", "https://example.com/a/b?q=1", "none"},
		{"cross origin sends only the origin", "https://example.com/a/b?q=1", "https://other.example/c", "https://example.com/", "none"},
		{"https downgrade sends nothing", "https://example.com/a", "http://example.com/b", "", ""},
		{"http upgrade is cross origin", "http://example.com/a", "https://example.com/b", "http://example.com/", "none"},
		{"default port is same origin", "https://example.com:443/a", "https://example.com/b", "https://example.com:443/a", "none"},
		{"different port is cross origin", "https://example.com:8443/a", "https://example.com/b", "https://example.com:8443/", "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev, err := url.Parse(tc.prev)
			if err != nil {
				t.Fatal(err)
			}
			next, err := url.Parse(tc.next)
			if err != nil {
				t.Fatal(err)
			}
			// A typed URL starts at Sec-Fetch-Site: none.
			via := []*http.Request{{URL: prev, Header: http.Header{}}}
			via[0].Header.Set("Sec-Fetch-Site", "none")
			req := &http.Request{URL: next, Header: http.Header{}}
			req.Header.Set("Sec-Fetch-Site", "none")
			if err := BrowserCheckRedirect(req, via); err != nil {
				t.Fatalf("BrowserCheckRedirect: %v", err)
			}
			if got := req.Header.Get("Referer"); got != tc.wantReferer {
				t.Errorf("Referer = %q, want %q", got, tc.wantReferer)
			}
			if got := req.Header.Get("Sec-Fetch-Site"); got != tc.wantSite {
				t.Errorf("Sec-Fetch-Site = %q, want %q", got, tc.wantSite)
			}
		})
	}
}

func TestRedirectSite(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		chain  []string
		target string
		want   string
	}{
		{"same origin", "https://example.com/a", []string{"https://example.com/a"}, "https://example.com/b", "same-origin"},
		{"cross-origin same-site", "https://example.com/a", []string{"https://example.com/a"}, "https://sub.example.com/b", "same-site"},
		{"cross-site", "https://example.com/a", []string{"https://example.com/a"}, "https://example.net/b", "cross-site"},
		{"scheme change is cross-site", "https://example.com/a", []string{"https://example.com/a"}, "http://example.com/b", "cross-site"},
		{"port change is same-site", "https://example.com:8443/a", []string{"https://example.com:8443/a"}, "https://example.com/b", "same-site"},
		{"same ip other port is same-site", "http://127.0.0.1:1/a", []string{"http://127.0.0.1:1/a"}, "http://127.0.0.1:2/b", "same-site"},
		{"different ip is cross-site", "http://127.0.0.1:1/a", []string{"http://127.0.0.1:1/a"}, "http://127.0.0.2/b", "cross-site"},
		{"public suffix separates hosts", "https://a.github.io/x", []string{"https://a.github.io/x"}, "https://b.github.io/y", "cross-site"},
		{"co.uk subdomains are same-site", "https://sub.example.co.uk/x", []string{"https://sub.example.co.uk/x"}, "https://example.co.uk/y", "same-site"},
		{"chain never recovers", "https://example.com/a", []string{"https://example.com/a", "https://sub.example.com/b", "https://example.net/c"}, "https://example.com/d", "cross-site"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin, err := url.Parse(tc.origin)
			if err != nil {
				t.Fatal(err)
			}
			via := make([]*http.Request, len(tc.chain))
			for i, raw := range tc.chain {
				u, err := url.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				via[i] = &http.Request{URL: u, Header: http.Header{}}
			}
			target, err := url.Parse(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if got := redirectSite(origin, via, target); got != tc.want {
				t.Errorf("redirectSite = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBrowserRedirectSecFetchSite(t *testing.T) {
	newReq := func(method, raw, site, origin string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := &http.Request{Method: method, URL: u, Header: http.Header{}}
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}

	t.Run("form redirect cross-site", func(t *testing.T) {
		init := newReq(http.MethodPost, "https://html.duckduckgo.com/html/", "same-origin", "https://html.duckduckgo.com")
		req := newReq(http.MethodGet, "https://example.net/result", "same-origin", "")
		if err := BrowserCheckRedirect(req, []*http.Request{init}); err != nil {
			t.Fatal(err)
		}
		for k, want := range map[string]string{
			"Sec-Fetch-Site": "cross-site",
			"Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-User": "?1",
			"Sec-Fetch-Dest": "document",
		} {
			if got := req.Header.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
	})

	t.Run("form redirect same-site", func(t *testing.T) {
		init := newReq(http.MethodPost, "https://html.duckduckgo.com/html/", "same-origin", "https://html.duckduckgo.com")
		req := newReq(http.MethodGet, "https://duckduckgo.com/result", "same-origin", "")
		if err := BrowserCheckRedirect(req, []*http.Request{init}); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Sec-Fetch-Site"); got != "same-site" {
			t.Errorf("Sec-Fetch-Site = %q, want same-site", got)
		}
	})

	t.Run("typed navigation keeps none", func(t *testing.T) {
		init := newReq(http.MethodGet, "https://example.com/", "none", "")
		req := newReq(http.MethodGet, "https://example.net/", "none", "")
		if err := BrowserCheckRedirect(req, []*http.Request{init}); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Sec-Fetch-Site"); got != "none" {
			t.Errorf("Sec-Fetch-Site = %q, want none", got)
		}
	})

	t.Run("insecure form upgrade is cross-site", func(t *testing.T) {
		init := newReq(http.MethodPost, "http://example.com/form", "", "http://example.com")
		req := newReq(http.MethodGet, "https://example.net/result", "", "")
		if err := BrowserCheckRedirect(req, []*http.Request{init}); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Sec-Fetch-Site"); got != "cross-site" {
			t.Errorf("Sec-Fetch-Site = %q, want cross-site", got)
		}
		if got := req.Header.Get("Sec-Fetch-Mode"); got != "navigate" {
			t.Errorf("Sec-Fetch-Mode = %q, want navigate", got)
		}
	})

	t.Run("insecure typed upgrade keeps none", func(t *testing.T) {
		init := newReq(http.MethodGet, "http://example.com/", "", "")
		req := newReq(http.MethodGet, "https://example.net/", "", "")
		if err := BrowserCheckRedirect(req, []*http.Request{init}); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Sec-Fetch-Site"); got != "none" {
			t.Errorf("Sec-Fetch-Site = %q, want none", got)
		}
		if got := req.Header.Get("Sec-Fetch-Mode"); got != "navigate" {
			t.Errorf("Sec-Fetch-Mode = %q, want navigate", got)
		}
	})

	t.Run("downgrade removes fetch metadata", func(t *testing.T) {
		init := newReq(http.MethodGet, "https://example.com/", "none", "")
		req := newReq(http.MethodGet, "http://example.com/", "none", "")
		if err := BrowserCheckRedirect(req, []*http.Request{init}); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest"} {
			if got := req.Header.Get(k); got != "" {
				t.Errorf("%s = %q, want absent on plain HTTP", k, got)
			}
		}
	})
}

func TestBrowserRedirectDropsFormHeaders(t *testing.T) {
	prev, _ := url.Parse("https://example.com/form")
	next, _ := url.Parse("https://example.com/result")

	// 301/302/303: net/http turns the POST into a GET. Origin and Content-Type
	// belong to the form submission, so a browser drops them.
	req := &http.Request{Method: http.MethodGet, URL: next, Header: http.Header{}}
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := BrowserCheckRedirect(req, []*http.Request{{Method: http.MethodPost, URL: prev, Header: http.Header{}}}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Origin"); got != "" {
		t.Errorf("Origin after POST->GET redirect = %q, want absent", got)
	}
	if got := req.Header.Get("Content-Type"); got != "" {
		t.Errorf("Content-Type after POST->GET redirect = %q, want absent", got)
	}

	// 307/308 keeps the POST, so the form headers stay.
	req = &http.Request{Method: http.MethodPost, URL: next, Header: http.Header{}}
	req.Header.Set("Origin", "https://example.com")
	if err := BrowserCheckRedirect(req, []*http.Request{{Method: http.MethodPost, URL: prev, Header: http.Header{}}}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Origin"); got != "https://example.com" {
		t.Errorf("Origin on 307 redirect = %q, want it preserved", got)
	}
}

func TestBrowserRedirectLimit(t *testing.T) {
	via := make([]*http.Request, 10)
	for i := range via {
		u, _ := url.Parse("https://example.com/a")
		via[i] = &http.Request{URL: u, Header: http.Header{}}
	}
	req := &http.Request{URL: via[9].URL, Header: http.Header{}}
	if err := BrowserCheckRedirect(req, via); err == nil {
		t.Fatal("the 11th request should hit the redirect limit")
	}
}
