package controllers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/phillip/vault/config"
	"github.com/phillip/vault/models"
	"github.com/phillip/vault/utils"
)

//
// ================== EXPORT ==================
//

// Export Credentials to Excel
func ExportCredentialsExcel(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := config.GetCollection("credentials").Find(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer cursor.Close(ctx)

	var credentials []*models.Credential
	if err := cursor.All(ctx, &credentials); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	f := excelize.NewFile()
	sheet := "Credentials"
	f.NewSheet(sheet)

	// Headers
	headers := []string{"ID", "UserID", "SiteName", "Username", "Password", "LoginURL", "Notes", "Category"}
	for i, h := range headers {
		cell := string(rune('A' + i)) + "1"
		f.SetCellValue(sheet, cell, h)
	}

	// Rows
	for i, cred := range credentials {

		row := strconv.Itoa(i + 2)
		// 🔑 decrypt password before exporting
		password, _ := utils.Decrypt(cfg.AESKey, cred.PasswordEncrypted)
		if err != nil {
			password = "[decryption error]"
		}
		f.SetCellValue(sheet, "A"+row, cred.ID.Hex())
		f.SetCellValue(sheet, "B"+row, cred.UserID.Hex())
		f.SetCellValue(sheet, "C"+row, cred.SiteName)
		f.SetCellValue(sheet, "D"+row, cred.Username)
		f.SetCellValue(sheet, "E"+row, password)
		f.SetCellValue(sheet, "F"+row, cred.LoginURL)
		f.SetCellValue(sheet, "G"+row, cred.Notes)
		f.SetCellValue(sheet, "H"+row, cred.Category)
	}

	c.Header("Content-Disposition", "attachment; filename=credentials.xlsx")
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

	if err := f.Write(c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	}
}

// Export Subscriptions to Excel
func ExportSubscriptionsExcel(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := config.GetCollection("subscriptions").Find(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer cursor.Close(ctx)

	var subscriptions []*models.Subscription
	if err := cursor.All(ctx, &subscriptions); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	f := excelize.NewFile()
	sheet := "Subscriptions"
	f.NewSheet(sheet)

	// Headers
	headers := []string{"ID", "ServiceName", "PlanName", "StartDate", "RenewalDate", "Price", "Currency", "Status"}
	for i, h := range headers {
		cell := string(rune('A' + i)) + "1"
		f.SetCellValue(sheet, cell, h)
	}

	// Rows
	for i, s := range subscriptions {
		row := strconv.Itoa(i + 2)
		f.SetCellValue(sheet, "A"+row, s.ID.Hex())
		f.SetCellValue(sheet, "B"+row, s.ServiceName)
		f.SetCellValue(sheet, "C"+row, s.PlanName)

		if s.StartDate != nil {
			f.SetCellValue(sheet, "D"+row, s.StartDate.Format("2006-01-02"))
		}
		if s.RenewalDate != nil {
			f.SetCellValue(sheet, "E"+row, s.RenewalDate.Format("2006-01-02"))
		}

		f.SetCellValue(sheet, "F"+row, s.Price)
		f.SetCellValue(sheet, "G"+row, s.Currency)
		f.SetCellValue(sheet, "H"+row, s.Status)
	}

	c.Header("Content-Disposition", "attachment; filename=subscriptions.xlsx")
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

	if err := f.Write(c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

// Export Resources to Excel
func ExportResourcesExcel(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := config.GetCollection("hubs").Find(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer cursor.Close(ctx)

	var hubs []*models.Hub
	if err := cursor.All(ctx, &hubs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	f := excelize.NewFile()
	sheet := "Hubs"
	f.NewSheet(sheet)

	// Headers
	headers := []string{"ID", "Title", "Type", "Value", "Notes", "CreatedAt"}
	for i, h := range headers {
		cell := string(rune('A' + i)) + "1"
		f.SetCellValue(sheet, cell, h)
	}

	// Rows
	for i, s := range hubs {
		row := strconv.Itoa(i + 2)
		f.SetCellValue(sheet, "A"+row, s.ID.Hex())
		f.SetCellValue(sheet, "B"+row, s.Title)
		f.SetCellValue(sheet, "C"+row, s.Type)
		f.SetCellValue(sheet, "D"+row, s.Value)
		f.SetCellValue(sheet, "E"+row, s.Notes)
		f.SetCellValue(sheet, "F"+row, s.CreatedAt)
	}

	c.Header("Content-Disposition", "attachment; filename=resources.xlsx")
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

	if err := f.Write(c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

//
// ================== IMPORT ==================
//

// Import Credentials from Excel
func ImportCredentialsExcel(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Get logged-in user ID from context
		uid := c.GetString("user_id")
		if uid == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		userID, err := primitive.ObjectIDFromHex(uid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id"})
			return
		}

		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
			return
		}

		src, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer src.Close()

		f, err := excelize.OpenReader(src)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Excel file"})
			return
		}

		rows, err := f.GetRows("Credentials")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "sheet Credentials not found"})
			return
		}

		var credentials []*models.Credential
		for i, row := range rows {
			if i == 0 {
				continue // skip header
			}
			if len(row) < 8 {
				continue
			}

			enc, err := utils.Encrypt(cfg.AESKey, row[4])
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt password"})
				return
			}

			cred := &models.Credential{
				ID:                primitive.NewObjectID(),
				UserID:            userID,
				SiteName:          row[2],
				Username:          row[3],
				PasswordEncrypted: enc,
				LoginURL:          row[5],
				Notes:             row[6],
				Category:          row[7],
				CreatedAt:         time.Now(),
				UpdatedAt:         time.Now(),
			}
			credentials = append(credentials, cred)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var docs []any
		for _, cred := range credentials {
			docs = append(docs, cred)
		}

		if _, err := config.GetCollection("credentials").InsertMany(ctx, docs); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"imported": len(credentials)})
	}
}

// Import Subscriptions from Excel
func ImportSubscriptionsExcel(c *gin.Context) {
	// 1. Get logged-in user ID from context
    uid := c.GetString("user_id")
    if uid == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return
    }

    userID, err := primitive.ObjectIDFromHex(uid)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id"})
        return
    }

	// 2. Handle uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer src.Close()

	f, err := excelize.OpenReader(src)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Excel file"})
		return
	}

	rows, err := f.GetRows("Subscriptions")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sheet Subscriptions not found"})
		return
	}

	// 3. Build subscription list
	var subs []*models.Subscription
	for i, row := range rows {
		if i == 0 {
			continue // skip header
		}
		if len(row) < 8 {
			continue
		}
		price, _ := strconv.ParseFloat(row[5], 64)

		subs = append(subs, &models.Subscription{
			ID:          primitive.NewObjectID(),
			UserID:      userID,         // 🔑 attach logged-in user
			ServiceName: row[1],
			PlanName:    row[2],
			Price:       price,
			Currency:    row[6],
			Status:      row[7],
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
	}

	// 4. Insert into MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var docs []interface{}
	for _, s := range subs {
		docs = append(docs, s)
	}

	if _, err := config.GetCollection("subscriptions").InsertMany(ctx, docs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"imported": len(subs)})
}

// Import Resources from Excel
func ImportResourcesExcel(c *gin.Context) {
	// 1. Get logged-in user ID from context
    uid := c.GetString("user_id")
    if uid == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return
    }

    userID, err := primitive.ObjectIDFromHex(uid)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id"})
        return
    }

	// 2. Handle uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer src.Close()

	f, err := excelize.OpenReader(src)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Excel file"})
		return
	}

	rows, err := f.GetRows("Hubs")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sheet Hubs not found"})
		return
	}

	// 3. Build Hubs list
	var hubs []*models.Hub
	for i, row := range rows {
		if i == 0 {
			continue // skip header
		}
		if len(row) < 8 {
			continue
		}

		hubs = append(hubs, &models.Hub{
			ID:         primitive.NewObjectID(),
			UserID:		userID,         // 🔑 attach logged-in user
			Title:		row[1],
			Type: 		row[2],
			Value:  	row[5],
			Notes:		row[6],
			CreatedAt:	time.Now(),
			UpdatedAt:	time.Now(),
		})
	}

	// 4. Insert into MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var docs []interface{}
	for _, s := range hubs {
		docs = append(docs, s)
	}

	if _, err := config.GetCollection("hubs").InsertMany(ctx, docs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"imported": len(hubs)})
}
