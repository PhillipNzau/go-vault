package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/phillip/vault/config"
	"github.com/phillip/vault/controllers"
	"github.com/phillip/vault/middleware"
)

func SetupRoutes(r *gin.Engine, cfg *config.Config) {
	// public
	r.POST("/auth/register", controllers.Register(cfg))
	r.POST("/auth/login", controllers.Login(cfg))

	// protected
	auth := middleware.AuthMiddleware(cfg)
	creds := r.Group("/credentials")
	creds.Use(auth)
	{
		creds.POST("", controllers.CreateCredential(cfg))
		creds.GET("", controllers.ListCredentials(cfg))
		creds.GET(":id", controllers.GetCredential(cfg))
		creds.PUT(":id", controllers.UpdateCredential(cfg))
		creds.DELETE(":id", controllers.DeleteCredential(cfg))
	}

	subs := r.Group("/subscriptions")
	subs.Use(auth)
	{
		subs.POST("", controllers.CreateSubscription(cfg))
		subs.GET("", controllers.ListSubscriptions(cfg))
		subs.GET(":id", controllers.GetSubscription(cfg))
		subs.PUT(":id", controllers.UpdateSubscription(cfg))
		subs.DELETE(":id", controllers.DeleteSubscription(cfg))
	}

	// analytics
	r.GET("/analytics/subscriptions", auth, controllers.MonthlySummary(cfg))
}
