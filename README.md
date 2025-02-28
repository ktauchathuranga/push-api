# Push API Documentation

## Overview
A production-ready API for user authentication and push notification management using Firebase Cloud Messaging (FCM). Features JWT authentication, secure credential storage, and bulk notification delivery.

---

## Table of Contents
- [Push API Documentation](#push-api-documentation)
  - [Overview](#overview)
  - [Table of Contents](#table-of-contents)
  - [Authentication](#authentication)
    - [JWT Bearer Tokens](#jwt-bearer-tokens)
  - [Endpoints](#endpoints)
    - [1. User Registration](#1-user-registration)
    - [2. User Login](#2-user-login)
    - [3. Store FCM Token](#3-store-fcm-token)
    - [4. Send Notifications](#4-send-notifications)
  - [Setup Guide](#setup-guide)
    - [1. Server Requirements](#1-server-requirements)
    - [2. Environment Configuration](#2-environment-configuration)
    - [3. Database Schema](#3-database-schema)
    - [4. Firebase Configuration](#4-firebase-configuration)
  - [Testing](#testing)
    - [1. Registration Test](#1-registration-test)
    - [2. Load Testing](#2-load-testing)
  - [Security](#security)
    - [1. Encryption](#1-encryption)
    - [2. Credential Handling](#2-credential-handling)
    - [3. Input Validation](#3-input-validation)
  - [Rate Limiting](#rate-limiting)
  - [Monitoring](#monitoring)
    - [Key Metrics](#key-metrics)
    - [Alert Thresholds](#alert-thresholds)
  - [Best Practices](#best-practices)
    - [1. Client Implementation](#1-client-implementation)
    - [2. Notification Design](#2-notification-design)
  - [Troubleshooting](#troubleshooting)
    - [Common Errors](#common-errors)
    - [Log Analysis](#log-analysis)

---

## Authentication
### JWT Bearer Tokens
```http
Authorization: Bearer <your_jwt_token>
```

1. Obtain token via `/login` endpoint
2. Token expires in 1 hour (3600 seconds)
3. Required for protected endpoints:
   - `/send-notification`

---

## Endpoints

### 1. User Registration
```http
POST / {action: "signup"}
```

**Request:**
```json
{
  "action": "signup",
  "username": "user@example.com",
  "password": "SecurePass123!"
}
```

**Validation Rules:**
- Username: 3-30 chars (`a-zA-Z0-9_-\.`)
- Password: 8-72 chars

**Responses:**
| Status | Description                  |
|--------|------------------------------|
| 201    | User created successfully    |
| 400    | Invalid input format         |
| 409    | Username already exists      |

---

### 2. User Login
```http
POST / {action: "login"}
```

**Request:**
```json
{
  "action": "login",
  "username": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Codes:**
| Status | Description                  |
|--------|------------------------------|
| 401    | Invalid credentials          |
| 429    | Too many failed attempts     |

---

### 3. Store FCM Token
```http
POST / {action: "store_token"}
```

**Request:**
```json
{
  "action": "store_token",
  "token": "fcm_token_from_device"
}
```

**Validation:**
- 152-character string format

**Responses:**
| Status | Description                  |
|--------|------------------------------|
| 200    | Token stored successfully    |
| 409    | Token already exists         |

---

### 4. Send Notifications
```http
POST / {action: "send_notification"}
```

**Request:**
```json
{
  "action": "send_notification",
  "title": "Server Alert",
  "body": "CPU usage at 95%"
}
```

**Headers:**
```http
Authorization: Bearer <your_jwt_token>
```

**Response:**
```json
{
  "message": "Notifications sent",
  "success_count": 145,
  "failure_count": 2
}
```

**Error Codes:**
| Status | Description                  |
|--------|------------------------------|
| 401    | Invalid/missing JWT          |
| 403    | Insufficient permissions     |
| 429    | Rate limit exceeded          |

---

## Setup Guide

### 1. Server Requirements
- PHP 8.1+ with extensions:
  - openssl
  - pdo_mysql
  - curl
- MySQL 8.0+
- Firebase Project

### 2. Environment Configuration
`.env` file:
```ini
DB_HOST=mysql-host
DB_NAME=push_db
DB_USER=api_user
DB_PASS=Str0ngP@ss!
JWT_SECRET=your_256bit_secret_here
```

### 3. Database Schema
```sql
CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(30) UNIQUE NOT NULL,
  password_hash CHAR(60) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcm_tokens (
  token VARCHAR(152) PRIMARY KEY,
  user_id INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### 4. Firebase Configuration
1. Download service account JSON from Firebase Console
2. Save as `service-account.json` in project root
3. Set permissions:
   ```bash
   chmod 640 service-account.json
   ```

---

## Testing

### 1. Registration Test
```bash
curl -X POST https://api.example.com/ \
  -H "Content-Type: application/json" \
  -d '{
    "action": "signup",
    "username": "test@example.com",
    "password": "TestPass123!"
  }'
```

### 2. Load Testing
```bash
wrk -t4 -c100 -d30s \
  -s post.lua \
  http://api.example.com/
```

---

## Security

### 1. Encryption
- HTTPS mandatory for all endpoints
- TLS 1.3 required
- HSTS header enforced

### 2. Credential Handling
- Password hashing: bcrypt (cost 12)
- JWT secret: 256-bit minimum
- Key rotation:
  - JWT secret: 90 days
  - Database credentials: 180 days

### 3. Input Validation
```php
// Username validation
if (!preg_match('/^[\w\-.]{3,30}$/', $username)) {
  throw new InvalidInputException();
}

// Notification content
if (strlen($title) > 255 || strlen($body) > 1024) {
  throw new ContentTooLongException();
}
```

---

## Rate Limiting
| Endpoint            | Limit          |
|---------------------|----------------|
| /login              | 10 req/min     |
| /signup             | 5 req/min      |
| /send_notification  | 100 req/hour   |

---

## Monitoring

### Key Metrics
```prometheus
# HELP api_requests_total Total API requests
api_requests_total{endpoint="signup"} 142

# HELP notification_success Successfully delivered notifications
notification_success 2345

# HELP auth_failures Authentication failures
auth_failures 23
```

### Alert Thresholds
- Error rate > 5% for 5 minutes
- Auth failures > 20/min
- Notification success rate < 95%

---

## Best Practices

### 1. Client Implementation
```javascript
// Store token securely
async function storeFCMToken(token) {
  try {
    await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getJWT()}`
      },
      body: JSON.stringify({
        action: 'store_token',
        token: token
      })
    });
  } catch (error) {
    retryWithExponentialBackoff();
  }
}
```

### 2. Notification Design
- Prioritize critical alerts
- Include deep links
- Localize content
- Add urgency indicators
- Provide opt-out mechanism

---

## Troubleshooting

### Common Errors
| Code | Message                  | Resolution               |
|------|--------------------------|--------------------------|
| 401  | Invalid JWT              | Refresh authentication   |
| 429  | Too many requests        | Implement backoff        |
| 503  | Service unavailable      | Check Firebase status    |

### Log Analysis
```log
[2023-08-20T14:23:45+00:00] [ERROR] [500] Database connection failed
[2023-08-20T14:24:01+00:00] [WARN] [429] Rate limit exceeded from 192.168.1.1
```