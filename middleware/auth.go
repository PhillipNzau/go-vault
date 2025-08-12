package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/phillip/vault/config"
)

func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}
		// support optional "Bearer " prefix
		if after, ok :=strings.CutPrefix(token, "Bearer "); ok  {
			token = after
		}
		uid, err := parseToken(token, cfg)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set("user_id", uid)
		c.Next()
	}
}

func parseToken(tokenString string, cfg *config.Config) (primitive.ObjectID, error) {
	if tokenString == "" {
		return primitive.NilObjectID, errors.New("token empty")
	}
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return cfg.JWTSecret, nil
	})
	if err != nil || !token.Valid {
		return primitive.NilObjectID, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return primitive.NilObjectID, errors.New("invalid claims")
	}
	uidStr, ok := claims["user_id"].(string)
	if !ok {
		return primitive.NilObjectID, errors.New("invalid user_id in token")
	}
	uid, err := primitive.ObjectIDFromHex(uidStr)
	if err != nil {
		return primitive.NilObjectID, err
	}
	return uid, nil
}