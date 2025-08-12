package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/phillip/vault/config"
	"github.com/phillip/vault/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func CreateVaultItem(c *gin.Context) {
    var item models.VaultItem
    if err := c.ShouldBindJSON(&item); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    item.ID = primitive.NewObjectID()
    item.CreatedAt = time.Now()
    item.UpdatedAt = time.Now()
    _, err := config.GetCollection("vault").InsertOne(context.Background(), item)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusCreated, item)
}

func GetVaultItems(c *gin.Context) {
    cur, err := config.GetCollection("vault").Find(context.Background(), bson.M{})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer cur.Close(context.Background())

    var items []models.VaultItem
    for cur.Next(context.Background()) {
        var item models.VaultItem
        cur.Decode(&item)
        items = append(items, item)
    }
    c.JSON(http.StatusOK, items)
}

func GetVaultItem(c *gin.Context) {
    id, _ := primitive.ObjectIDFromHex(c.Param("id"))
    var item models.VaultItem
    err := config.GetCollection("vault").FindOne(context.Background(), bson.M{"_id": id}).Decode(&item)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Item not found"})
        return
    }
    c.JSON(http.StatusOK, item)
}

func UpdateVaultItem(c *gin.Context) {
    id, _ := primitive.ObjectIDFromHex(c.Param("id"))
    var item models.VaultItem
    if err := c.ShouldBindJSON(&item); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    item.UpdatedAt = time.Now()
    _, err := config.GetCollection("vault").UpdateOne(context.Background(), bson.M{"_id": id}, bson.M{"$set": item})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Updated"})
}

func DeleteVaultItem(c *gin.Context) {
    id, _ := primitive.ObjectIDFromHex(c.Param("id"))
    _, err := config.GetCollection("vault").DeleteOne(context.Background(), bson.M{"_id": id})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Deleted"})
}
