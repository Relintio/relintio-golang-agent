package relintio

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

func GinMiddleware(agent *Agent) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip internal checks
		path := c.Request.URL.Path
		if path == "/_relintio/challenge" || path == "/_relintio/verify" {
			c.Next()
			return
		}

		res := agent.CheckRequest(c.Request)
		agent.SendTelemetry(c.Request, res)

		if res.Action == "block" {
			c.Header("Content-Type", "text/html")
			c.String(http.StatusForbidden, `<!DOCTYPE html><html><head><title>Access Denied</title><style>body{background:#000;color:#fff;font-family:sans-serif;padding:50px;text-align:center;}</style></head><body><h1>403 Forbidden</h1><p>Request blocked by Relintio WAF protection.</p></body></html>`)
			c.Abort()
			return
		}

		if res.Action == "challenge" {
			challengeURL := fmt.Sprintf("/_relintio/challenge?ref=%s", url.QueryEscape(path))
			c.Header("X-Relintio-Action", "challenge")
			c.Header("X-Relintio-Challenge-URL", challengeURL)
			c.Header("Content-Type", "text/html")
			c.String(http.StatusForbidden, fmt.Sprintf(`<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><script>window.location.href="%s";</script></body></html>`, challengeURL))
			c.Abort()
			return
		}

		c.Next()
	}
}
