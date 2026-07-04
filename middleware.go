package relintio

import (
	"fmt"
	"net/http"
)

func Middleware(agent *Agent) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip security check for internal challenge routes
			if r.URL.Path == "/_relintio/challenge" || r.URL.Path == "/_relintio/verify" {
				next.ServeHTTP(w, r)
				return
			}

			res := agent.CheckRequest(r)
			agent.SendTelemetry(r, res)

			if res.Action == "block" {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Access Denied</title><style>body{background:#000;color:#fff;font-family:sans-serif;padding:50px;text-align:center;}</style></head><body><h1>403 Forbidden</h1><p>Request blocked by Relintio WAF protection.</p></body></html>`)
				return
			}

			if res.Action == "challenge" {
				challengeURL := fmt.Sprintf("/_relintio/challenge?ref=%s", r.URL.Path)
				w.Header().Set("X-Relintio-Action", "challenge")
				w.Header().Set("X-Relintio-Challenge-URL", challengeURL)
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><script>window.location.href="%s";</script></body></html>`, challengeURL)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
