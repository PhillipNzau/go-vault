package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"github.com/phillip/vault/config"
	"github.com/phillip/vault/models"
	"github.com/phillip/vault/utils"
)

// =============================
// Register
// =============================
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

		// Check if email already exists
		count, _ := users.CountDocuments(ctx, bson.M{"email": input.Email})
		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}

		// Hash password
		hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)

		user := models.User{
			ID:           primitive.NewObjectID(),
			Name:         input.Name,
			Email:        input.Email,
			PasswordHash: string(hash),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// Insert new user
		if _, err := users.InsertOne(ctx, user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
			return
		}

		// Generate OTP
		otp := fmt.Sprintf("%06d", rand.Intn(1000000))
		expiry := time.Now().Add(10 * time.Minute)

		users.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"otp": otp, "otp_expiry": expiry}})

		// Send OTP email
		go utils.SendEmail(user.Email, "Verify your account", "Your OTP is: "+otp)

		c.JSON(http.StatusCreated, gin.H{
			"status":  200,
			"message": "Registration successful, OTP sent to email",
			"user": gin.H{
				"id":    user.ID.Hex(),
				"name":  user.Name,
				"email": user.Email,
			},
		})
	}
}

// =============================
// Login
// =============================
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

		// Compare password
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		// Generate OTP
		otp := fmt.Sprintf("%06d", rand.Intn(1000000))
		expiry := time.Now().Add(10 * time.Minute)

		users.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"otp": otp, "otp_expiry": expiry}})

		// Send OTP email
		go utils.SendEmail(user.Email, "Your Login OTP", "Your OTP is: "+otp)

		c.JSON(http.StatusOK, gin.H{
			"status":  200,
			"message": "Login successful, OTP sent to email",
		})
	}
}

// =============================
// Verify OTP (new endpoint)
// =============================
func VerifyOTP(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input struct {
			Email string `json:"email" binding:"required,email"`
			OTP   string `json:"otp" binding:"required"`
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
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid otp"})
			return
		}

		if user.OTP != input.OTP || time.Now().After(user.OTPExpiry) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "otp expired or invalid"})
			return
		}

		// Clear OTP
		users.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$unset": bson.M{"otp": "", "otp_expiry": ""}})

		// Create tokens
		accessToken, refreshToken, _ := createTokensForUser(user.ID, cfg)
		users.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"refresh_token": refreshToken}})

		c.JSON(http.StatusOK, gin.H{
			"status":        200,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"user": gin.H{
				"id":    user.ID.Hex(),
				"name":  user.Name,
				"email": user.Email,
			},
		})
	}
}

// =============================
// Refresh Token
// =============================
func RefreshToken(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing refresh_token"})
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(input.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
			return cfg.JWTSecret, nil
		})
		if err != nil || !token.Valid || claims["type"] != "refresh" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		uid, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user_id"})
			return
		}

		users := cfg.MongoClient.Database(cfg.DBName).Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user models.User
		objID, _ := primitive.ObjectIDFromHex(uid)
		if err := users.FindOne(ctx, bson.M{"_id": objID}).Decode(&user); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		if user.RefreshToken != input.RefreshToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token mismatch"})
			return
		}

		// Create new tokens
		accessToken, refreshToken, _ := createTokensForUser(user.ID, cfg)

		// Rotate refresh token
		users.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"refresh_token": refreshToken}})

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

// =============================
// Helpers
// =============================
func createTokensForUser(uid primitive.ObjectID, cfg *config.Config) (accessToken string, refreshToken string, err error) {
	// Access Token (short-lived)
	accessClaims := jwt.MapClaims{
		"user_id": uid.Hex(),
		"exp":     time.Now().Add(15 * time.Minute).Unix(), // 15 minutes
		"iat":     time.Now().Unix(),
	}
	access := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = access.SignedString(cfg.JWTSecret)
	if err != nil {
		return "", "", err
	}

	// Refresh Token (long-lived)
	refreshClaims := jwt.MapClaims{
		"user_id": uid.Hex(),
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(), // 7 days
		"iat":     time.Now().Unix(),
		"type":    "refresh",
	}
	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refresh.SignedString(cfg.JWTSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

