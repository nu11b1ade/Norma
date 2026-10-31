// Package httpx centralizes the client identities used for outbound requests.
//
// A request's User-Agent is only believable when the headers around it agree:
// navigation requests carry Accept + Sec-Fetch-*, browser fetches carry client
// hints, and an official SDK carries X-Stainless-*. Keeping each profile in one
// place keeps those values in sync — a UA that contradicts its companion headers
// is a stronger fingerprint than either value alone.
package httpx

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Browser profile: Google Chrome on macOS, pinned to the stable channel
// (2026-10). Blink freezes the macOS version at 10_15_7; the Chrome major in
// BrowserUserAgent and browserCHUA must match.
const (
	BrowserUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

	browserAccept         = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	browserAcceptLanguage = "en-US,en;q=0.9"
	browserCHUA           = `"Chromium";v="156", "Not_A Brand";v="24", "Google Chrome";v="156"`
	browserCHUAPlatform   = `"macOS"`
)

// setBrowserIdentity gives h the headers every Chrome request carries on a
// potentially trustworthy URL. Client hints (Sec-CH-UA*) are secure-context
// only, so they are omitted elsewhere (loopback is a secure context and keeps
// them). It is unexported because a real browser never sends these on their
// own: Chrome also adds Sec-Fetch-* on trustworthy URLs and, for cross-origin
// calls, Origin. Callers must use one of the full request profiles below
// instead of claiming a browser identity they cannot complete.
func setBrowserIdentity(h http.Header, trustworthy bool) {
	h.Set("User-Agent", BrowserUserAgent)
	h.Set("Accept-Language", browserAcceptLanguage)
	setClientHints(h, trustworthy)
}

func setClientHints(h http.Header, trustworthy bool) {
	if !trustworthy {
		h.Del("Sec-CH-UA")
		h.Del("Sec-CH-UA-Mobile")
		h.Del("Sec-CH-UA-Platform")
		return
	}
	h.Set("Sec-CH-UA", browserCHUA)
	h.Set("Sec-CH-UA-Mobile", "?0")
	h.Set("Sec-CH-UA-Platform", browserCHUAPlatform)
}

// SetBrowserNavigation makes h look like a top-level navigation to a typed URL.
func SetBrowserNavigation(h http.Header, target string) {
	setNavigation(h, "none", potentiallyTrustworthyURL(target))
}

// SetBrowserFormNavigation makes h look like a same-origin form submission
// from page, the absolute http(s) URL of the page hosting the form. Origin is
// derived from that page; Referer names it directly.
func SetBrowserFormNavigation(h http.Header, page string) {
	u, err := url.Parse(page)
	valid := err == nil && u.Scheme != "" && u.Host != ""
	setNavigation(h, "same-origin", valid && potentiallyTrustworthy(u))
	if valid {
		h.Set("Origin", u.Scheme+"://"+u.Host)
		h.Set("Referer", page)
	}
}

func setNavigation(h http.Header, site string, trustworthy bool) {
	setBrowserIdentity(h, trustworthy)
	h.Set("Accept", browserAccept)
	// Unlike Fetch Metadata, Upgrade-Insecure-Requests is sent on plain HTTP
	// too: its whole purpose is asking an insecure page to upgrade.
	h.Set("Upgrade-Insecure-Requests", "1")
	if trustworthy {
		setFetchMetadata(h, site)
	}
}

func setFetchMetadata(h http.Header, site string) {
	h.Set("Sec-Fetch-Site", site)
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-User", "?1")
	h.Set("Sec-Fetch-Dest", "document")
}

func clearFetchMetadata(h http.Header) {
	h.Del("Sec-Fetch-Site")
	h.Del("Sec-Fetch-Mode")
	h.Del("Sec-Fetch-User")
	h.Del("Sec-Fetch-Dest")
}

// Official Go SDK versions whose default request headers the model adapters
// reproduce (pinned 2026-10). The UA and X-Stainless-Package-Version must name
// the same release. Anthropic v1.84.0 is the newest v1 release; it defaults to
// anthropic-version 2023-06-01, matching Norma's default API version. (The v2
// line defaults to 2026-10-21, which would contradict the header.)
const (
	AnthropicSDKVersion = "1.84.0"
	OpenAISDKVersion    = "3.91.0"
)

// SetAnthropicSDK adds the headers anthropic-sdk-go sends on every request.
func SetAnthropicSDK(h http.Header) {
	h.Set("User-Agent", "Anthropic/Go "+AnthropicSDKVersion)
	h.Set("Accept", "application/json")
	setStainless(h, AnthropicSDKVersion)
}

// SetOpenAISDK adds the headers openai-go sends on every request.
func SetOpenAISDK(h http.Header) {
	h.Set("User-Agent", "OpenAI/Go "+OpenAISDKVersion)
	h.Set("Accept", "application/json")
	setStainless(h, OpenAISDKVersion)
}

// BrowserCheckRedirect applies Chrome's redirect behavior to every hop:
//   - strict-origin-when-cross-origin referrer policy (net/http's default
//     sends the full previous URL on every hop);
//   - client hints and Fetch Metadata are present only on potentially
//     trustworthy targets;
//   - Sec-Fetch-Site is recomputed over the whole redirect chain.
//
// It intentionally leaves a typed navigation's Sec-Fetch-Site: none alone;
// the Fetch Metadata algorithm preserves that value across redirects.
func BrowserCheckRedirect(req *http.Request, via []*http.Request) error {
	// Match net/http's built-in redirect limit.
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1].URL
	req.Header.Del("Referer")
	trustworthy := potentiallyTrustworthy(req.URL)
	setClientHints(req.Header, trustworthy)
	if trustworthy {
		setFetchMetadata(req.Header, redirectFetchSite(via, req.URL))
	} else {
		clearFetchMetadata(req.Header)
	}
	// net/http rewrites 301/302/303 redirects to GET but copies the original
	// request's headers. A browser navigation GET carries neither of these.
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		req.Header.Del("Origin")
		req.Header.Del("Content-Type")
	}
	switch {
	case prev.Scheme == "https" && req.URL.Scheme != "https":
		// HTTPS -> HTTP downgrade: the browser withholds the referrer entirely.
	case sameOrigin(prev, req.URL):
		u := *prev
		u.User = nil
		u.Fragment = ""
		u.RawFragment = ""
		req.Header.Set("Referer", u.String())
	default:
		req.Header.Set("Referer", prev.Scheme+"://"+strings.ToLower(prev.Host)+"/")
	}
	return nil
}

// redirectFetchSite implements Fetch Metadata's set-site algorithm over the
// full redirect chain. The initiator's site mode comes from the first request:
// an explicitly user-initiated navigation ("none") stays none; otherwise the
// value is recomputed from every URL in the chain.
func redirectFetchSite(via []*http.Request, target *url.URL) string {
	init := via[0]
	switch init.Header.Get("Sec-Fetch-Site") {
	case "none":
		return "none"
	case "":
		if init.Header.Get("Origin") == "" {
			// The initial URL was not potentially trustworthy, so Fetch
			// Metadata was omitted; no Origin identifies the typed-URL profile.
			return "none"
		}
	}
	origin := init.URL
	if raw := init.Header.Get("Origin"); raw != "" {
		if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
			origin = u
		}
	}
	return redirectSite(origin, via, target)
}

// redirectSite walks the full URL list, per Fetch Metadata's set-site
// algorithm. The value can only degrade: same-origin -> same-site ->
// cross-site, and a cross-site hop ends the walk permanently.
func redirectSite(origin *url.URL, via []*http.Request, target *url.URL) string {
	site := "same-origin"
	for _, r := range via {
		if sameOrigin(r.URL, origin) {
			continue
		}
		site = "cross-site"
		if !sameSite(origin, r.URL) {
			return site
		}
		site = "same-site"
	}
	if !sameOrigin(target, origin) {
		site = "cross-site"
		if sameSite(origin, target) {
			site = "same-site"
		}
	}
	return site
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		originPort(a) == originPort(b)
}

// sameSite follows HTML's schemeful same-site rule: the schemes must match and
// the hosts' registrable domains must be equal. Ports are ignored.
func sameSite(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	ah, bh := siteHost(a), siteHost(b)
	return ah != "" && strings.EqualFold(ah, bh)
}

// siteHost returns the host's registrable domain, or the host itself when it
// has none (IP addresses, localhost), per HTML's "obtain a site".
func siteHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

func potentiallyTrustworthyURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && potentiallyTrustworthy(u)
}

// potentiallyTrustworthy reports whether a browser treats u as a secure
// context for Client Hints and Fetch Metadata: HTTPS, or a loopback origin.
func potentiallyTrustworthy(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func originPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// setStainless mirrors the platform properties Stainless-generated Go SDKs
// attach. X-Stainless-Timeout is deliberately absent: the official SDK removes
// it when no request timeout is configured, which is Norma's case.
func setStainless(h http.Header, version string) {
	h.Set("X-Stainless-Lang", "go")
	h.Set("X-Stainless-Package-Version", version)
	h.Set("X-Stainless-OS", sdkOS())
	h.Set("X-Stainless-Arch", sdkArch())
	h.Set("X-Stainless-Runtime", "go")
	h.Set("X-Stainless-Runtime-Version", runtime.Version())
	h.Set("X-Stainless-Retry-Count", "0")
}

func sdkOS() string {
	switch runtime.GOOS {
	case "ios":
		return "iOS"
	case "android":
		return "Android"
	case "darwin":
		return "MacOS"
	case "windows":
		return "Windows"
	case "freebsd":
		return "FreeBSD"
	case "openbsd":
		return "OpenBSD"
	case "linux":
		return "Linux"
	default:
		return fmt.Sprintf("Other:%s", runtime.GOOS)
	}
}

func sdkArch() string {
	switch runtime.GOARCH {
	case "386":
		return "x32"
	case "amd64":
		return "x64"
	case "arm":
		return "arm"
	case "arm64":
		return "arm64"
	default:
		return fmt.Sprintf("other:%s", runtime.GOARCH)
	}
}
