package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"github.com/phillip/vault/config"
	"github.com/phillip/vault/models"
)

func Register(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input struct {
			Name     string `json:"name" binding:"required"`
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required,min=8"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		users := cfg.MongoClient.Database(cfg.DBName).Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		count, _ := users.CountDocuments(ctx, bson.M{"email": input.Email})
		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		user := models.User{ID: primitive.NewObjectID(), Name: input.Name, Email: input.Email, PasswordHash: string(hash), CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if _, err := users.InsertOne(ctx, user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
			return
		}
		token, _ := createTokenForUser(user.ID, cfg)
		c.JSON(http.StatusCreated, gin.H{"token": token, "user": gin.H{"id": user.ID.Hex(), "name": user.Name, "email": user.Email}})
	}
}

func Login(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		users := cfg.MongoClient.Database(cfg.DBName).Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var user models.User
		if err := users.FindOne(ctx, bson.M{"email": input.Email}).Decode(&user); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		token, _ := createTokenForUser(user.ID, cfg)
		c.JSON(http.StatusOK, gin.H{"token": token, "user": gin.H{"id": user.ID.Hex(), "name": user.Name, "email": user.Email}})
	}
}

func createTokenForUser(uid primitive.ObjectID, cfg *config.Config) (string, error) {
	claims := jwt.MapClaims{"user_id": uid.Hex(), "exp": time.Now().Add(72 * time.Hour).Unix(), "iat": time.Now().Unix()}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(cfg.JWTSecret)
}