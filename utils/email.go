package utils

import (
	"log"
	"os"

	"gopkg.in/gomail.v2"
)

func SendEmail(to, subject, body string) error {
	from := os.Getenv("EMAIL_FROM")       
	smtpUser := os.Getenv("SMTP_USER")    
	smtpPass := os.Getenv("SMTP_PASS")    
	smtpHost := os.Getenv("SMTP_HOST")    
	smtpPort := 587                        

	if from == "" || smtpUser == "" || smtpPass == "" || smtpHost == "" {
		log.Println("Missing one or more required SMTP environment variables")
		return nil
	}

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Failed to send email to %s: %v", to, err)
		return err
	}

	log.Printf("Email successfully sent to %s", to)
	return nil
}
