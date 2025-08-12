package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/phillip/vault/config"
	"github.com/phillip/vault/routes"
)

func main() {
	// load env
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file loaded, reading environment variables")
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("config load error: %v", err)
	}

	// setup DB & indexes inside config.Init (done in LoadConfig)

	r := gin.Default()

	routes.SetupRoutes(r, cfg)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s\n", port)
	r.Run(":" + port)
}