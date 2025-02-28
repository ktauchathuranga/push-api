# Push API

**Push API** is a robust, RESTful API for managing Firebase Cloud Messaging (FCM) tokens and sending push notifications. Built with PHP and dockerized for seamless deployment, it offers user authentication via JWT (JSON Web Tokens), an open endpoint to save FCM tokens, and a secure endpoint to send notifications. This project is designed for scalability, security, and ease of use in production environments.

## Features

- **User Authentication**:
  - **Signup**: Register new users with a username and password.
  - **Login**: Authenticate users and issue JWT tokens.
- **FCM Token Management**:
  - **Save FCM Token**: Store FCM tokens without authentication.
- **Notification Sending**:
  - Send customizable push notifications (title and body) to all stored FCM tokens using FCM v1 API.
- **Security**:
  - JWT-based authentication for sending notifications.
  - Password hashing with PHP’s `password_hash`.
  - Input validation and secure error handling.
- **Deployment**:
  - Dockerized with MySQL (database), PHP-FPM (API), and Nginx (web server).
  - Configurable via environment variables.

## Project Structure

```
push-api/
├── api/
│   ├── index.php         # Main API script handling all endpoints
│   ├── Dockerfile        # PHP-FPM Dockerfile
│   └── logs/             # Directory for API logs
├── sql/
│   └── init.sql          # Database schema and initial data
├── nginx.conf            # Nginx configuration
├── docker-compose.yml    # Docker Compose configuration
├── service-account.json  # Firebase service account file (not included)
└── README.md             # This file
```

## Prerequisites

- **Docker**: Version 20.10 or higher.
- **Docker Compose**: Version 1.29 or higher.
- **Firebase Service Account**: A `service-account.json` file from your Firebase project (Firebase Console > Project Settings > Service Accounts).
- **Basic Knowledge**: Familiarity with REST APIs, JSON, and command-line interfaces.

## Setup Instructions

### 1. Clone or Create the Project
If using a repository:
```bash
git clone <repository-url> push-api
cd push-api
```
Alternatively, manually create the folder structure and copy the files.

### 2. Add Firebase Service Account
- Place your `service-account.json` file in the project root (`push-api/`).
- Ensure it corresponds to your Firebase project with FCM enabled.

### 3. Configure Environment
Edit `docker-compose.yml` to set a secure `JWT_SECRET`:
```yaml
environment:
  JWT_SECRET: your_secure_jwt_secret_here  # Replace with a strong secret
```

### 4. Create Logs Directory
```bash
mkdir -p api/logs
```

### 5. Start the Application
Launch the services with Docker Compose:
```bash
docker-compose up -d
```
- This starts MySQL, PHP-FPM, and Nginx in the background.
- Allow a few seconds for MySQL to initialize the database.

### 6. Verify Setup
Confirm all services are running:
```bash
docker ps
```
Expect to see: `push-api_db_1`, `push-api_php_1`, and `push-api_nginx_1`.

## API Endpoints

### Base URL
`http://localhost` (default port 80)

### 1. POST `/signup`
Register a new user.

#### Request
- **Method**: POST
- **Content-Type**: `application/json`
- **Body**:
  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```
  - `username`: String (unique, max 50 characters).
  - `password`: String (minimum 6 characters).

#### Response
- **Success (200)**:
  ```json
  {"message": "User created successfully"}
  ```
- **Error (400)**: Invalid input.
  ```json
  {"error": "Invalid username or password (min 6 chars)"}
  ```
- **Error (409)**: Username already exists.
  ```json
  {"error": "Username already exists"}
  ```
- **Error (500)**: Server error.
  ```json
  {"error": "Internal server error"}
  ```

#### Example
```bash
curl -X POST http://localhost/signup \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "securepass123"}'
```

---

### 2. POST `/login`
Authenticate a user and obtain a JWT token.

#### Request
- **Method**: POST
- **Content-Type**: `application/json`
- **Body**:
  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```

#### Response
- **Success (200)**:
  ```json
  {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
  ```
- **Error (400)**: Missing fields.
  ```json
  {"error": "Missing username or password"}
  ```
- **Error (401)**: Invalid credentials.
  ```json
  {"error": "Invalid credentials"}
  ```
- **Error (500)**: Server error.
  ```json
  {"error": "Internal server error"}
  ```

#### Example
```bash
curl -X POST http://localhost/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "securepass123"}'
```

---

### 3. POST `/store-token`
Store an FCM token (open endpoint, no authentication required).

#### Request
- **Method**: POST
- **Content-Type**: `application/json`
- **Body**:
  ```json
  {
    "token": "your_fcm_token_here"
  }
  ```
  - `token`: String (valid FCM token).

#### Response
- **Success (200)**:
  ```json
  {"message": "FCM token saved successfully"}
  ```
- **Error (400)**: Invalid input.
  ```json
  {"error": "Invalid or missing token"}
  ```
- **Error (409)**: Token already exists.
  ```json
  {"error": "Token already exists"}
  ```
- **Error (500)**: Server error.
  ```json
  {"error": "Internal server error"}
  ```

#### Example
```bash
curl -X POST http://localhost/store-token \
     -H "Content-Type: application/json" \
     -d '{"token": "your_fcm_token_here"}'
```

---

### 4. POST `/send-notification`
Send push notifications to all stored FCM tokens (requires JWT authentication).

#### Request
- **Method**: POST
- **Headers**:
  - `Authorization: Bearer <your_jwt_token>`
  - `Content-Type: application/json`
- **Body**:
  ```json
  {
    "title": "Notification Title",
    "body": "Notification Body"
  }
  ```

#### Response
- **Success (200)**:
  ```json
  {
    "message": "Notifications sent",
    "success_count": 1,
    "failure_count": 0
  }
  ```
- **Error (400)**: Missing fields.
  ```json
  {"error": "Missing title or body"}
  ```
- **Error (401)**: Invalid or missing JWT.
  ```json
  {"error": "Unauthorized"}
  ```
- **Error (500)**: Server error.
  ```json
  {"error": "Internal server error"}
  ```

#### Example
```bash
curl -X POST http://localhost/send-notification \
     -H "Authorization: Bearer <your_jwt_token>" \
     -H "Content-Type: application/json" \
     -d '{"title": "Test", "body": "Hello World"}'
```

---

## Authentication Flow

1. **Register**: Use `/signup` to create a user account.
2. **Login**: Authenticate with `/login` to receive a JWT token.
3. **Send Notifications**: Use the JWT in the `Authorization` header for `/send-notification`.

The JWT expires after 1 hour. Re-authenticate with `/login` to get a new token if it expires.

## Saving FCM Tokens
- Use `/store-token` to store tokens from devices without authentication.
- Tokens are stored in the `fcm_tokens` table with a unique constraint.

## Troubleshooting

- **Container Logs**:
  ```bash
  docker logs push-api_php_1
  ```
- **API Logs**: Check `api/logs/api.log` for detailed error messages.
- **Database Issues**: Ensure MySQL is running (`docker ps`) and the schema loaded correctly.
- **FCM Failures**: Verify `service-account.json` is valid and matches your Firebase project.

## Production Considerations

- **HTTPS**: Deploy with an HTTPS-enabled reverse proxy (e.g., Nginx with SSL certificates).
- **JWT Secret**: Store `JWT_SECRET` in a secure environment variable or secret manager (e.g., AWS Secrets Manager).
- **Rate Limiting**: Apply rate limiting to `/store-token` to prevent abuse (e.g., via Nginx or an API gateway).
- **Scaling**: Add more PHP-FPM containers behind a load balancer for high traffic.
- **Monitoring**: Integrate logging with a centralized system (e.g., ELK Stack).
- **Backup**: Regularly back up the MySQL `db_data` volume.

## Stopping the Application

To stop and remove containers:
```bash
docker-compose down
```
To also remove the database volume:
```bash
docker-compose down -v
```

## Contributing

Contributions are welcome! Fork the repository, submit issues, or create pull requests. Ensure changes maintain security, performance, and code quality standards.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details (create one if needed).