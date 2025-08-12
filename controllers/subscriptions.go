package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/phillip/vault/config"
	"github.com/phillip/vault/models"
)

func CreateSubscription(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.GetString("user_id")
		userID, _ := primitive.ObjectIDFromHex(uid)
		var input struct {
			ServiceName string  `json:"service_name" binding:"required"`
			PlanName    string  `json:"plan_name"`
			StartDate   string  `json:"start_date"`
			RenewalDate string  `json:"renewal_date"`
			Price       float64 `json:"price" binding:"required"`
			Currency    string  `json:"currency" binding:"required"`
			Status      string  `json:"status" binding:"required"`
			Notes       string  `json:"notes"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var sd, rd *time.Time
		if input.StartDate != "" { if t, err := time.Parse(time.RFC3339, input.StartDate); err == nil { sd = &t } }
		if input.RenewalDate != "" { if t, err := time.Parse(time.RFC3339, input.RenewalDate); err == nil { rd = &t } }
		sub := models.Subscription{ID: primitive.NewObjectID(), UserID: userID, ServiceName: input.ServiceName, PlanName: input.PlanName, StartDate: sd, RenewalDate: rd, Price: input.Price, Currency: input.Currency, Status: input.Status, Notes: input.Notes, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		col := cfg.MongoClient.Database(cfg.DBName).Collection("subscriptions")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := col.InsertOne(ctx, sub); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save"}); return }
		c.JSON(http.StatusCreated, gin.H{"id": sub.ID.Hex(), "message": "created"})
	}
}

func ListSubscriptions(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.GetString("user_id")
		userID, _ := primitive.ObjectIDFromHex(uid)
		col := cfg.MongoClient.Database(cfg.DBName).Collection("subscriptions")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		filter := bson.M{"user_id": userID}
		if status := c.Query("status"); status != "" { filter["status"] = status }
		cursor, err := col.Find(ctx, filter)
		if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "fetch failed"}); return }
		var subs []models.Subscription
		if err := cursor.All(ctx, &subs); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "decode failed"}); return }
		c.JSON(http.StatusOK, subs)
	}
}

func GetSubscription(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.GetString("user_id")
		userID, _ := primitive.ObjectIDFromHex(uid)
		id := c.Param("id")
		oid, _ := primitive.ObjectIDFromHex(id)
		col := cfg.MongoClient.Database(cfg.DBName).Collection("subscriptions")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var sub models.Subscription
		if err := col.FindOne(ctx, bson.M{"_id": oid, "user_id": userID}).Decode(&sub); err != nil { c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
		c.JSON(http.StatusOK, sub)
	}
}

func UpdateSubscription(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.GetString("user_id")
		userID, _ := primitive.ObjectIDFromHex(uid)
		id := c.Param("id")
		oid, _ := primitive.ObjectIDFromHex(id)
		var input struct {
			ServiceName string  `json:"service_name"`
			PlanName    string  `json:"plan_name"`
			StartDate   string  `json:"start_date"`
			RenewalDate string  `json:"renewal_date"`
			Price       *float64 `json:"price"`
			Currency    string  `json:"currency"`
			Status      string  `json:"status"`
			Notes       string  `json:"notes"`
		}
		if err := c.ShouldBindJSON(&input); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
		update := bson.M{"updated_at": time.Now()}
		if input.ServiceName != "" { update["service_name"] = input.ServiceName }
		if input.PlanName != "" { update["plan_name"] = input.PlanName }
		if input.StartDate != "" { if t, err := time.Parse(time.RFC3339, input.StartDate); err == nil { update["start_date"] = t } }
		if input.RenewalDate != "" { if t, err := time.Parse(time.RFC3339, input.RenewalDate); err == nil { update["renewal_date"] = t } }
		if input.Price != nil { update["price"] = *input.Price }
		if input.Currency != "" { update["currency"] = input.Currency }
		if input.Status != "" { update["status"] = input.Status }
		if input.Notes != "" { update["notes"] = input.Notes }
		col := cfg.MongoClient.Database(cfg.DBName).Collection("subscriptions")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := col.UpdateOne(ctx, bson.M{"_id": oid, "user_id": userID}, bson.M{"$set": update})
		if err != nil || res.MatchedCount == 0 { c.JSON(http.StatusNotFound, gin.H{"error": "not found or not owned"}); return }
		c.JSON(http.StatusOK, gin.H{"message": "updated"})
	}
}

func DeleteSubscription(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.GetString("user_id")
		userID, _ := primitive.ObjectIDFromHex(uid)
		id := c.Param("id")
		oid, _ := primitive.ObjectIDFromHex(id)
		col := cfg.MongoClient.Database(cfg.DBName).Collection("subscriptions")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := col.DeleteOne(ctx, bson.M{"_id": oid, "user_id": userID})
		if err != nil || res.DeletedCount == 0 { c.JSON(http.StatusNotFound, gin.H{"error": "not found or not owned"}); return }
		c.JSON(http.StatusOK, gin.H{"message": "deleted"})
	}
}