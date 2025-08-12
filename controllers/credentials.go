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
	"github.com/phillip/vault/utils"
)

// CreateCredential - Add new password/credential
func CreateCredential(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.GetString("user_id")
		userID, _ := primitive.ObjectIDFromHex(uid)
		

		var input struct {
			SiteName string `json:"site_name" binding:"required"`
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
			LoginURL string `json:"login_url"`
			Notes    string `json:"notes"`
			Category string `json:"category"`
		}

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Encrypt password
		enc, err := utils.Encrypt(cfg.AESKey, input.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
			return
		}

		cred := models.Credential{
			ID:                primitive.NewObjectID(),
			UserID:            userID,
			SiteName:          input.SiteName,
			Username:          input.Username,
			PasswordEncrypted: enc,
			LoginURL:          input.LoginURL,
			Notes:             input.Notes,
			Category:          input.Category,
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		col := cfg.MongoClient.Database(cfg.DBName).Collection("credentials")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := col.InsertOne(ctx, cred); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save credential"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"id": cred.ID.Hex(), "message": "credential created"})
	}
}

// ListCredentials - Show all credentials for logged-in user
func ListCredentials(cfg *config.Config) gin.HandlerFunc {
    return func(c *gin.Context) {
        uid := c.GetString("user_id")
        userID, _ := primitive.ObjectIDFromHex(uid)

        col := cfg.MongoClient.Database(cfg.DBName).Collection("credentials")
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        filter := bson.M{"user_id": userID}

        // Optional search
        if q := c.Query("q"); q != "" {
            filter["$or"] = bson.A{
                bson.M{"site_name": bson.M{"$regex": q, "$options": "i"}},
                bson.M{"username": bson.M{"$regex": q, "$options": "i"}},
            }
        }

        cursor, err := col.Find(ctx, filter)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "could not fetch credentials"})
            return
        }

        var creds []models.Credential
        if err := cursor.All(ctx, &creds); err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "could not decode creds"})
            return
        }

        // Decrypt passwords for output
        out := make([]gin.H, 0, len(creds))
        for _, cr := range creds {
            pass, _ := utils.Decrypt(cfg.AESKey, cr.PasswordEncrypted)
            out = append(out, gin.H{
                "id":         cr.ID.Hex(),
                "site_name":  cr.SiteName,
                "username":   cr.Username,
                "password":   pass,
                "login_url":  cr.LoginURL,
                "notes":      cr.Notes,
                "category":   cr.Category,
                "created_at": cr.CreatedAt,
                "updated_at": cr.UpdatedAt,
            })
        }

        c.JSON(http.StatusOK, out)
    }
}


// GetCredential - Fetch single credential
func GetCredential(cfg *config.Config) gin.HandlerFunc {
    return func(c *gin.Context) {
        uid := c.GetString("user_id")
        userID, _ := primitive.ObjectIDFromHex(uid)

        credID, err := primitive.ObjectIDFromHex(c.Param("id"))
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
            return
        }

        var credential models.Credential
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        err = cfg.MongoClient.Database(cfg.DBName).
            Collection("credentials").
            FindOne(ctx, bson.M{"_id": credID, "user_id": userID}).
            Decode(&credential)

        if err != nil {
            c.JSON(http.StatusNotFound, gin.H{"error": "credential not found or not owned"})
            return
        }

        pass, _ := utils.Decrypt(cfg.AESKey, credential.PasswordEncrypted)
        credential.PasswordEncrypted = pass

        c.JSON(http.StatusOK, credential)
    }
}


// UpdateCredential - Edit credential
func UpdateCredential(cfg *config.Config) gin.HandlerFunc {
    return func(c *gin.Context) {
        uid := c.GetString("user_id")
        userID, _ := primitive.ObjectIDFromHex(uid)

        oid, err := primitive.ObjectIDFromHex(c.Param("id"))
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
            return
        }

        var input struct {
            SiteName string `json:"site_name"`
            Username string `json:"username"`
            Password string `json:"password"`
            LoginURL string `json:"login_url"`
            Notes    string `json:"notes"`
            Category string `json:"category"`
        }

        if err := c.ShouldBindJSON(&input); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        // Ensure ownership
        col := cfg.MongoClient.Database(cfg.DBName).Collection("credentials")
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        var existingCredential models.Credential
        err = col.FindOne(ctx, bson.M{"_id": oid, "user_id": userID}).Decode(&existingCredential)
        if err != nil {
            c.JSON(http.StatusNotFound, gin.H{"error": "credential not found or not owned"})
            return
        }

        update := bson.M{"updated_at": time.Now()}

        if input.SiteName != "" {
            update["site_name"] = input.SiteName
        }
        if input.Username != "" {
            update["username"] = input.Username
        }
        if input.Password != "" {
            enc, err := utils.Encrypt(cfg.AESKey, input.Password)
            if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
                return
            }
            update["password_encrypted"] = enc
        }
        if input.LoginURL != "" {
            update["login_url"] = input.LoginURL
        }
        if input.Notes != "" {
            update["notes"] = input.Notes
        }
        if input.Category != "" {
            update["category"] = input.Category
        }

        res, err := col.UpdateOne(ctx, bson.M{"_id": oid, "user_id": userID}, bson.M{"$set": update})
        if err != nil || res.MatchedCount == 0 {
            c.JSON(http.StatusNotFound, gin.H{"error": "not found or not owned"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "updated"})
    }
}


// DeleteCredential - Remove credential
func DeleteCredential(cfg *config.Config) gin.HandlerFunc {
    return func(c *gin.Context) {
        uid := c.GetString("user_id")
        userID, _ := primitive.ObjectIDFromHex(uid)

        oid, err := primitive.ObjectIDFromHex(c.Param("id"))
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
            return
        }

        col := cfg.MongoClient.Database(cfg.DBName).Collection("credentials")
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        // Ensure ownership before deletion
        res, err := col.DeleteOne(ctx, bson.M{"_id": oid, "user_id": userID})
        if err != nil || res.DeletedCount == 0 {
            c.JSON(http.StatusNotFound, gin.H{"error": "not found or not owned"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "deleted"})
    }
}

