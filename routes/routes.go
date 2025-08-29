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
	r.POST("/auth/refresh", controllers.RefreshToken(cfg))

	// otp
	r.POST("/auth/request-otp", controllers.RequestOTP(cfg))
	r.POST("/auth/verify-otp", controllers.VerifyOTP(cfg))

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

	export := r.Group("/export")
	export.Use(auth)

	{
		// Export
	export.GET("/credentials/excel", controllers.ExportCredentialsExcel(cfg))
	export.GET("/subscriptions/excel", controllers.ExportSubscriptionsExcel)
	export.GET("/resources/excel", controllers.ExportResourcesExcel)
	}

	imports := r.Group("/import")
	imports.Use(auth)

	{
		// Import
	imports.POST("/credentials/excel", controllers.ImportCredentialsExcel(cfg))
	imports.POST("/subscriptions/excel", controllers.ImportSubscriptionsExcel)
	// imports.POST("/resources/excel", controllers.ImportResourcesExcel)
	}

	hubs := r.Group("/hubs")
	hubs.Use(auth)
	
	{
		hubs.POST("", controllers.CreateHub(cfg))
		hubs.GET("", controllers.ListHubs(cfg))
		hubs.GET(":id", controllers.GetHub(cfg))
		hubs.PUT("/update/:id", controllers.UpdateHub(cfg))
		hubs.DELETE("/delete/:id", controllers.DeleteHub(cfg))
	}

	// analytics
	r.GET("/analytics/subscriptions", auth, controllers.MonthlySummary(cfg))

}
