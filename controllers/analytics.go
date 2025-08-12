package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/phillip/vault/config"
)

// MonthlySummary - Only the authenticated user gets their own summary
func MonthlySummary(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the owner's user_id from authentication middleware
		uid := c.GetString("user_id")
		userID, _ := primitive.ObjectIDFromHex(uid)

		col := cfg.MongoClient.Database(cfg.DBName).Collection("subscriptions")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Restrict aggregation to only user's subscriptions
		matchStage := bson.D{{"$match", bson.D{{"user_id", userID}, {"status", "active"}}}}
		groupStage := bson.D{{"$group", bson.D{{"_id", "$currency"}, {"total", bson.D{{"$sum", "$price"}}}}}}
		pipeline := mongo.Pipeline{matchStage, groupStage}

		cursor, err := col.Aggregate(ctx, pipeline)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "aggregation failed"})
			return
		}
		var out []bson.M
		if err := cursor.All(ctx, &out); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "decode failed"})
			return
		}
		c.JSON(http.StatusOK, out)
	}
}