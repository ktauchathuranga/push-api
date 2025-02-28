<?php
declare(strict_types=1);

// ==============================
// Environment Configuration
// ==============================
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/logs/api.log');
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');

// ==============================
// Security Constants
// ==============================
define('MAX_PW_LENGTH', 72);  // BCrypt limitation
define('MIN_PW_LENGTH', 8);
define('USERNAME_REGEX', '/^[a-zA-Z0-9_\-.]{3,30}$/');
define('FCM_TOKEN_LENGTH', 152);
define('JWT_EXPIRATION', 3600);  // 1 hour

// ==============================
// JWT Implementation
// ==============================
final class JWT
{
    public static function encode(array $payload, string $secret): string
    {
        $header = json_encode(['alg' => 'HS256', 'typ' => 'JWT']);
        $payload = json_encode(array_merge($payload, ['iat' => time()]));
        
        $b64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $b64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        $signature = hash_hmac('sha256', "$b64Header.$b64Payload", $secret, true);
        $b64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        return "$b64Header.$b64Payload.$b64Signature";
    }

    public static function decode(string $token, string $secret): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        [$b64Header, $b64Payload, $b64Signature] = $parts;

        $signature = base64_decode(str_replace(['-', '_'], ['+', '/'], $b64Signature));
        $expectedSig = hash_hmac('sha256', "$b64Header.$b64Payload", $secret, true);

        if (!hash_equals($signature, $expectedSig)) {
            return null;
        }

        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $b64Payload)), true);
        
        if (($payload['exp'] ?? 0) < time()) {
            return null;
        }

        return $payload;
    }
}

// ==============================
// Database Layer
// ==============================
final class Database
{
    private static ?PDO $instance = null;

    public static function get(): PDO
    {
        if (self::$instance === null) {
            $dsn = sprintf(
                'mysql:host=%s;dbname=%s;charset=utf8mb4',
                getenv('DB_HOST'),
                getenv('DB_NAME')
            );

            self::$instance = new PDO($dsn, getenv('DB_USER'), getenv('DB_PASS'), [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_PERSISTENT => false
            ]);
        }
        return self::$instance;
    }
}

// ==============================
// Request Validation
// ==============================
final class Validator
{
    public static function username(string $username): void
    {
        if (!preg_match(USERNAME_REGEX, $username)) {
            throw new InvalidArgumentException('Invalid username format', 400);
        }
    }

    public static function password(string $password): void
    {
        if (strlen($password) < MIN_PW_LENGTH || strlen($password) > MAX_PW_LENGTH) {
            throw new InvalidArgumentException(
                sprintf('Password must be between %d-%d characters', MIN_PW_LENGTH, MAX_PW_LENGTH),
                400
            );
        }
    }

    public static function fcmToken(string $token): void
    {
        if (strlen($token) !== FCM_TOKEN_LENGTH) {
            throw new InvalidArgumentException('Invalid FCM token format', 400);
        }
    }
}

// ==============================
// Main Application
// ==============================
try {
    // Validate request method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('Method Not Allowed', 405);
    }

    // Parse and validate input
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $action = $input['action'] ?? '';

    // Initialize database connection early
    $pdo = Database::get();

    switch ($action) {
        case 'signup':
            // Validate input
            $username = $input['username'] ?? '';
            $password = $input['password'] ?? '';
            
            Validator::username($username);
            Validator::password($password);

            // Check existing user
            $stmt = $pdo->prepare('SELECT 1 FROM users WHERE username = ?');
            $stmt->execute([$username]);
            
            if ($stmt->fetch()) {
                throw new RuntimeException('Username already exists', 409);
            }

            // Create user
            $stmt = $pdo->prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
            $stmt->execute([$username, password_hash($password, PASSWORD_BCRYPT)]);
            
            http_response_code(201);
            echo json_encode(['message' => 'User created']);
            break;

        case 'login':
            $username = $input['username'] ?? '';
            $password = $input['password'] ?? '';
            
            Validator::username($username);
            Validator::password($password);

            // Find user
            $stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE username = ?');
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if (!$user || !password_verify($password, $user['password_hash'])) {
                throw new RuntimeException('Invalid credentials', 401);
            }

            // Generate JWT
            $token = JWT::encode([
                'sub' => $user['id'],
                'exp' => time() + JWT_EXPIRATION
            ], getenv('JWT_SECRET'));

            echo json_encode(['token' => $token]);
            break;

        case 'store_token':
            $token = $input['token'] ?? '';
            Validator::fcmToken($token);

            try {
                $pdo->prepare('INSERT INTO fcm_tokens (token) VALUES (?)')
                    ->execute([$token]);
                echo json_encode(['message' => 'Token stored']);
            } catch (PDOException $e) {
                if ($e->errorInfo[1] === 1062) {
                    throw new RuntimeException('Token exists', 409);
                }
                throw new RuntimeException('Database error', 500);
            }
            break;

        case 'send_notification':
            // Authentication
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if (!preg_match('/Bearer\s+(.+)$/i', $authHeader, $matches)) {
                throw new RuntimeException('Missing token', 401);
            }

            $payload = JWT::decode($matches[1], getenv('JWT_SECRET'));
            if (!$payload) {
                throw new RuntimeException('Invalid token', 401);
            }

            // Validate input
            $title = trim($input['title'] ?? '');
            $body = trim($input['body'] ?? '');
            
            if (strlen($title) < 1 || strlen($title) > 255 || strlen($body) < 1) {
                throw new InvalidArgumentException('Invalid notification content', 400);
            }

            // Firebase authentication
            $serviceAccount = json_decode(
                file_get_contents(__DIR__ . '/service-account.json'),
                true
            ) ?? throw new RuntimeException('Service account error', 500);

            // [Remaining Firebase implementation...]
            // (Keep your existing Firebase implementation with added error handling)

            break;

        default:
            throw new RuntimeException('Invalid action', 404);
    }
} catch (InvalidArgumentException $e) {
    http_response_code($e->getCode() ?: 400);
    echo json_encode(['error' => $e->getMessage(), 'code' => $e->getCode()]);
} catch (RuntimeException $e) {
    $code = $e->getCode() ?: 500;
    http_response_code($code);
    echo json_encode(['error' => $e->getMessage(), 'code' => $code]);
} catch (Throwable $e) {
    error_log('Critical Error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Internal Server Error', 'code' => 500]);
}