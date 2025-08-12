# Password & Subscription Manager

A web application that helps users securely manage their passwords, login details, and subscriptions.  
Built with **Angular** (frontend), **Go (Gin)** (backend), and **MongoDB** (database).

## Features

### Password Management

- Store multiple login credentials securely
- View saved credentials with website name, URL, username, and password
- Search and filter credentials
- Edit or delete saved credentials

### Subscription Management

- Track active subscriptions (e.g., Netflix, Starlink, YouTube)
- Store subscription details: service name, cost, renewal date, and login credentials
- Send reminders for upcoming renewals
- Categorize subscriptions by type

### Security

- Password hashing and encryption for sensitive data
- JWT-based authentication
- HTTPS ready

---

## Tech Stack

- **Frontend**: Angular
- **Backend**: Go (Gin framework)
- **Database**: MongoDB

---

## API Endpoints

### Authentication

- `POST /auth/register` – Register a new user
- `POST /auth/login` – Login and get JWT token

### Credentials

- `GET /credentials` – Get all credentials for logged-in user
- `POST /credentials` – Add a new credential
- `GET /credentials/:id` – Get a single credential
- `PUT /credentials/:id` – Update a credential
- `DELETE /credentials/:id` – Delete a credential

### Subscriptions

- `GET /subscriptions` – Get all subscriptions for logged-in user
- `POST /subscriptions` – Add a new subscription
- `GET /subscriptions/:id` – Get a single subscription
- `PUT /subscriptions/:id` – Update a subscription
- `DELETE /subscriptions/:id` – Delete a subscription

---

## ERD (Entity Relationship Diagram)

```
+----------------+      +--------------------+
|    Users       |      |   Credentials      |
+----------------+      +--------------------+
| id             | 1  n | id                 |
| name           |------| user_id            |
| email          |      | website_name       |
| password_hash  |      | website_url        |
+----------------+      | username           |
                         | password_encrypted |
                         +--------------------+

+----------------+
| Subscriptions  |
+----------------+
| id             |
| user_id        |
| service_name   |
| cost           |
| renewal_date   |
| login_username |
| login_password |
+----------------+
```

---

## Running Locally

### Prerequisites

- Go 1.21+
- MongoDB
- Node.js + Angular CLI

### Backend Setup

```bash
cd backend
go mod tidy
go run main.go
```

### Frontend Setup

```bash
cd frontend
npm install
ng serve
```

---
