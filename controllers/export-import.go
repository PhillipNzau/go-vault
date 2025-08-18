package controllers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gocarina/gocsv"
	"github.com/xuri/excelize/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/phillip/vault/config"
	"github.com/phillip/vault/models"
)

//
// ================== EXPORT ==================
//

// Export Credentials to CSV
func ExportCredentialsCSV(c *gin.Context) {
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

    // CSV-friendly version of Credential
    type CredentialCSV struct {
        ID       string `csv:"id"`
        UserID   string `csv:"user_id"`
        SiteName string `csv:"site_name"`
        Username string `csv:"username"`
        Password string `csv:"password"`
        LoginURL string `csv:"login_url"`
        Notes    string `csv:"notes"`
        Category string `csv:"category"`
    }

    var out []*CredentialCSV
    for _, cred := range credentials {
        out = append(out, &CredentialCSV{
            ID:       cred.ID.Hex(),
            UserID:   cred.UserID.Hex(),
            SiteName: cred.SiteName,
            Username: cred.Username,
            Password: cred.PasswordEncrypted,
            LoginURL: cred.LoginURL,
            Notes:    cred.Notes,
            Category: cred.Category,
        })
    }

    c.Header("Content-Disposition", "attachment; filename=credentials.csv")
    c.Header("Content-Type", "text/csv")

    if err := gocsv.Marshal(out, c.Writer); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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


//
// ================== IMPORT ==================
//

// Import Credentials from CSV
func ImportCredentialsCSV(c *gin.Context) {
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

	var credentials []*models.Credential
	if err := gocsv.Unmarshal(src, &credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid CSV format"})
		return
	}

	for _, cred := range credentials {
		cred.ID = primitive.NewObjectID()
		cred.CreatedAt = time.Now()
		cred.UpdatedAt = time.Now()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var docs []interface{}
	for _, c := range credentials {
		docs = append(docs, c)
	}

	if _, err := config.GetCollection("credentials").InsertMany(ctx, docs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"imported": len(credentials)})
}

// Import Subscriptions from Excel
func ImportSubscriptionsExcel(c *gin.Context) {
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

	var subs []*models.Subscription
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) < 8 {
			continue
		}
		price, _ := strconv.ParseFloat(row[5], 64)

		subs = append(subs, &models.Subscription{
			ID:          primitive.NewObjectID(),
			ServiceName: row[1],
			PlanName:    row[2],
			Price:       price,
			Currency:    row[6],
			Status:      row[7],
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
	}

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
