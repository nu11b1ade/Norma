package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/norma/internal/httpx"
)

// TestProviderRequestsCarrySDKIdentity verifies the adapters present the
// official SDK profile on the wire instead of Go's stock client UA.
func TestProviderRequestsCarrySDKIdentity(t *testing.T) {
	cases := []struct {
		name    string
		format  Format
		path    string
		body    string
		wantUA  string
		wantVer string
	}{
		{
			name:    "anthropic",
			format:  FormatAnthropic,
			path:    "/v1/messages",
			body:    `{"type":"message","content":[{"type":"text","text":"x"}],"stop_reason":"end_turn"}`,
			wantUA:  "Anthropic/Go " + httpx.AnthropicSDKVersion,
			wantVer: httpx.AnthropicSDKVersion,
		},
		{
			name:    "openai",
			format:  FormatOpenAI,
			path:    "/chat/completions",
			body:    `{"choices":[{"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}]}`,
			wantUA:  "OpenAI/Go " + httpx.OpenAISDKVersion,
			wantVer: httpx.OpenAISDKVersion,
		},
		{
			name:    "openai-responses",
			format:  FormatOpenAIResponses,
			path:    "/responses",
			body:    `{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"x"}]}],"status":"completed"}`,
			wantUA:  "OpenAI/Go " + httpx.OpenAISDKVersion,
			wantVer: httpx.OpenAISDKVersion,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotUA, gotLang, gotVer string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("path = %s, want %s", r.URL.Path, tc.path)
				}
				gotUA = r.Header.Get("User-Agent")
				gotLang = r.Header.Get("X-Stainless-Lang")
				gotVer = r.Header.Get("X-Stainless-Package-Version")
				w.Header().Set("content-type", "application/json")
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			p, err := NewProvider(Config{Format: tc.format, BaseURL: srv.URL, APIKey: "k", Model: "m"})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := p.Complete(context.Background(), CompletionRequest{Messages: []Message{UserText("go")}}); err != nil {
				t.Fatalf("complete: %v", err)
			}
			if gotUA != tc.wantUA {
				t.Errorf("User-Agent = %q, want %q", gotUA, tc.wantUA)
			}
			if gotLang != "go" {
				t.Errorf("X-Stainless-Lang = %q, want go", gotLang)
			}
			if gotVer != tc.wantVer {
				t.Errorf("X-Stainless-Package-Version = %q, want %q", gotVer, tc.wantVer)
			}
		})
	}
}
