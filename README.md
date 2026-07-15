# Relintio Go WAF Protection Agent SDK

Official Go middleware and SDK for integrating the Relintio WAF protection system.

## Installation

```bash
go get github.com/Relintio/relintio-golang-agent
```

## Features

- **Rule Cache Sync:** Periodically syncs active rules in a thread-safe background routine.
- **WAF Check Engine:** Instant threat analysis against local cached rules.
- **Middleware Adapters:** Built-in middleware for standard `net/http` and the `gin` framework.
- **Telemetry Loop:** Non-blocking telemetry reporting back to the Relintio console.

## Quickstart

### Standard `net/http` Integration

```go
package main

import (
    "net/http"
    "time"
    "github.com/Relintio/relintio-golang-agent"
)

func main() {
    agent := relintio.NewAgent(relintio.Config{
        LicenseKey:   "YOUR_LICENSE_KEY",
        Domain:       "example.com",
        ApiUrl:       "https://relintio.com/api",
        SyncInterval: 60 * time.Second,
    })
    
    agent.StartSync()
    defer agent.StopSync()

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Protected by Relintio"))
    })

    // Apply the standard middleware
    protectedHandler := relintio.Middleware(agent)(mux)

    http.ListenAndServe(":8080", protectedHandler)
}
```

### Gin Integration

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/Relintio/relintio-golang-agent"
)

func main() {
    agent := relintio.NewAgent(relintio.Config{
        LicenseKey: "YOUR_LICENSE_KEY",
        Domain: "example.com",
    })
    agent.StartSync()
    defer agent.StopSync()

    r := gin.Default()
    r.Use(relintio.GinMiddleware(agent))

    r.GET("/", func(c *gin.Context) {
        c.String(200, "Secure Route")
    })

    r.Run(":8080")
}
```
