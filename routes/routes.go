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
	cat := r.Group("/categories")
	cat.GET("", controllers.ListCategories(cfg))
	cat.GET(":id", controllers.GetCategory(cfg))
	cat.Use(auth)
	{
		cat.POST("", controllers.CreateCategory(cfg))
		cat.PUT("/update/:id", controllers.UpdateCategory(cfg))
		cat.DELETE("/delete/:id", controllers.DeleteCategory(cfg))
	}

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
