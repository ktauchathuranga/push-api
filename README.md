# Push API

A secure and scalable PHP-based API for handling user authentication, FCM token management, and push notification delivery using Firebase Cloud Messaging.

## Features

- JWT-based user authentication
- Secure password hashing with bcrypt
- FCM token storage and management
- Firebase Cloud Messaging integration
- Dockerized environment (PHP-FPM, MySQL, Nginx)
- Rate limiting and security headers
- Input validation and error handling
- Logging system

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Firebase Service Account JSON file
- PHP 8.2+ (for local development)

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/ktauchathuranga/push-api.git
cd push-api
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env file with your credentials
```

3. Initialize the project:
```bash
docker-compose up --build
```

4. Access the API at `http://localhost`

## API Documentation

### Endpoints

#### 1. User Registration
**POST /**  
Payload:
```json
{
  "action": "signup",
  "username": "testuser",
  "password": "SecurePass123!"
}
```

#### 2. User Login
**POST /**  
Payload:
```json
{
  "action": "login",
  "username": "testuser",
  "password": "SecurePass123!"
}
```

#### 3. Store FCM Token
**POST /**  
Payload:
```json
{
  "action": "store_token",
  "token": "your_fcm_token_here"
}
```

#### 4. Send Notification
**POST /**  
Headers:
```
Authorization: Bearer <JWT_TOKEN>
```
Payload:
```json
{
  "action": "send_notification",
  "title": "Hello World",
  "body": "This is a test notification"
}
```

## Configuration

### Environment Variables
- `DB_HOST`: MySQL database host
- `DB_NAME`: Database name
- `DB_USER`: Database user
- `DB_PASS`: Database password
- `JWT_SECRET`: Secret key for JWT encoding
- `FCM_TIMEOUT`: Firebase connection timeout (seconds)

### Security Settings
- JWT expiration: 1 hour
- Password requirements: 8-72 characters
- Username validation regex: `/^[a-zA-Z0-9_\-.]{3,30}$/`
- Security headers:
  - X-Content-Type-Options
  - X-Frame-Options
  - Content-Security-Policy
  - Referrer-Policy

## Project Structure

```
push-api/
├── api/
│   ├── logs/               # Error logs
│   ├── index.php           # Main application logic
│   └── Dockerfile          # PHP-FPM container configuration
├── sql/
│   └── init.sql            # Database schema
├── docker-compose.yml      # Service orchestration
├── nginx.conf              # Nginx server configuration
├── .env.example            # Environment template
└── service-account.json    # Firebase credentials
```

## Database Schema

```sql
CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(30) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fcm_tokens (
  id INT PRIMARY KEY AUTO_INCREMENT,
  token VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Error Handling

The API returns standardized JSON error responses with appropriate HTTP status codes:

```json
{
  "error": "Error message",
  "code": 400
}
```

Common error codes:
- 400: Bad Request
- 401: Unauthorized
- 404: Not Found
- 405: Method Not Allowed
- 409: Conflict
- 500: Internal Server Error

## Security Considerations

- All database queries use prepared statements
- Passwords stored using bcrypt algorithm
- JWT signature verification with HMAC-SHA256
- Input validation for all user-provided data
- Rate limiting through Nginx configuration
- Regular security header implementation
- Environment variables for sensitive data

## Deployment Notes

1. Replace `your_jwt_secret_here` with a strong secret key
2. Add valid Firebase service account JSON file
3. Configure Nginx for production:
   - Enable HTTPS with Let's Encrypt
   - Set appropriate rate limiting
   - Configure proper file permissions
4. Regular database backups
5. Monitor API logs for suspicious activity

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Submit pull request

## License

MIT License - See [LICENSE](LICENSE) for details

## Dependencies

- PHP 8.2+
- MySQL 8.0+
- Nginx
- Firebase Admin SDK
- OpenSSL
