package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Relintio/relintio-golang-agent"
)

func main() {
	// Initialize Relintio Agent
	agent := relintio.NewAgent(relintio.Config{
		LicenseKey:   "YOUR_LICENSE_KEY",
		ApiUrl:       "https://api.relintio.com/api",
		SyncInterval: 30 * time.Second,
	})

	// Start background rules synchronization
	agent.StartSync()

	r := gin.Default()

	// Apply Relintio WAF protection middleware
	r.Use(relintio.GinMiddleware(agent))

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Protected Go server is running",
		})
	})

	r.GET("/api/data", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   []string{"entry1", "entry2"},
		})
	})

	log.Println("Starting protected server on :8080...")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
