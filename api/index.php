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
define('MAX_PW_LENGTH', 72);
define('MIN_PW_LENGTH', 8);
define('USERNAME_REGEX', '/^[a-zA-Z0-9_\-.]{3,30}$/');
define('FCM_TOKEN_LENGTH', 142);
define('JWT_EXPIRATION', 3600);
define('FCM_TIMEOUT', 10);

// ==============================
// JWT Implementation
// ==============================
final class JWT {
    public static function encode(array $payload, string $secret): string {
        $header = json_encode(['alg' => 'HS256', 'typ' => 'JWT']);
        $payload = json_encode(array_merge($payload, ['iat' => time()]));
        
        $b64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $b64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        $signature = hash_hmac('sha256', "$b64Header.$b64Payload", $secret, true);
        $b64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        return "$b64Header.$b64Payload.$b64Signature";
    }

    public static function decode(string $token, string $secret): ?array {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;

        [$b64Header, $b64Payload, $b64Signature] = $parts;
        $signature = base64_decode(str_replace(['-', '_'], ['+', '/'], $b64Signature));
        $expectedSig = hash_hmac('sha256', "$b64Header.$b64Payload", $secret, true);

        if (!hash_equals($signature, $expectedSig)) return null;

        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $b64Payload)), true);
        return ($payload['exp'] ?? 0) >= time() ? $payload : null;
    }
}

// ==============================
// Database Layer
// ==============================
final class Database {
    private static ?PDO $instance = null;

    public static function get(): PDO {
        if (!self::$instance) {
            $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', 
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
final class Validator {
    public static function username(string $username): void {
        if (!preg_match(USERNAME_REGEX, $username)) {
            throw new InvalidArgumentException('Invalid username format', 400);
        }
    }

    public static function password(string $password): void {
        if (strlen($password) < MIN_PW_LENGTH || strlen($password) > MAX_PW_LENGTH) {
            throw new InvalidArgumentException(sprintf('Password must be %d-%d characters', MIN_PW_LENGTH, MAX_PW_LENGTH), 400);
        }
    }

    public static function fcmToken(string $token): void {
        if (strlen($token) !== FCM_TOKEN_LENGTH) {
            throw new InvalidArgumentException('Invalid FCM token', 400);
        }
    }

    public static function notificationContent(string $title, string $body): void {
        if (strlen($title) === 0 || strlen($title) > 255 || strlen($body) === 0) {
            throw new InvalidArgumentException('Invalid notification content', 400);
        }
    }
}

// ==============================
// Firebase Service
// ==============================
final class FirebaseService {
    public static function sendNotifications(string $title, string $body, array $tokens): array {
        $serviceAccount = self::getServiceAccount();
        $accessToken = self::getAccessToken($serviceAccount);
        return self::sendToFcm($title, $body, $tokens, $serviceAccount['project_id'], $accessToken);
    }

    private static function getServiceAccount(): array {
        $path = __DIR__ . '/app/service-account.json';
        if (!file_exists($path)) {
            throw new RuntimeException('Service account missing', 500);
        }
        
        $data = json_decode(file_get_contents($path), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('Invalid service account', 500);
        }
        
        return $data;
    }

    private static function getAccessToken(array $serviceAccount): string {
        $jwt = self::createOAuthJwt($serviceAccount);
        
        $ch = curl_init('https://oauth2.googleapis.com/token');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $jwt
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_TIMEOUT => 15
        ]);
        
        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status !== 200) {
            throw new RuntimeException('OAuth token failed', 500);
        }

        $data = json_decode($response, true);
        return $data['access_token'] ?? throw new RuntimeException('Invalid token response', 500);
    }

    private static function createOAuthJwt(array $serviceAccount): string {
        $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'iss' => $serviceAccount['client_email'],
            'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
            'aud' => 'https://oauth2.googleapis.com/token',
            'exp' => time() + 3600,
            'iat' => time()
        ]));

        $signature = '';
        openssl_sign(
            str_replace(['+', '/', '='], ['-', '_', ''], $header) . '.' . 
            str_replace(['+', '/', '='], ['-', '_', ''], $payload),
            $signature,
            $serviceAccount['private_key'],
            'SHA256'
        );

        return sprintf('%s.%s.%s',
            str_replace(['+', '/', '='], ['-', '_', ''], $header),
            str_replace(['+', '/', '='], ['-', '_', ''], $payload),
            str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature))
        );
    }

    private static function sendToFcm(string $title, string $body, array $tokens, string $projectId, string $accessToken): array {
        $success = 0;
        $url = "https://fcm.googleapis.com/v1/projects/$projectId/messages:send";
        $headers = [
            'Authorization: Bearer ' . $accessToken,
            'Content-Type: application/json',
            'Accept: application/json'
        ];

        foreach ($tokens as $token) {
            $payload = [
                'message' => [
                    'token' => $token,
                    'notification' => ['title' => $title, 'body' => $body]
                ]
            ];

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_POSTFIELDS => json_encode($payload),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => FCM_TIMEOUT
            ]);

            $response = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($status === 200) $success++;
            else error_log("FCM error: $status - $response");
        }

        return ['success' => $success, 'failure' => count($tokens) - $success];
    }
}

// ==============================
// Main Application
// ==============================
try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('Method Not Allowed', 405);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $action = $input['action'] ?? '';
    $pdo = Database::get();

    switch ($action) {
        case 'signup':
            $username = $input['username'] ?? '';
            $password = $input['password'] ?? '';
            Validator::username($username);
            Validator::password($password);

            $stmt = $pdo->prepare('SELECT 1 FROM users WHERE username = ?');
            $stmt->execute([$username]);
            if ($stmt->fetch()) throw new RuntimeException('Username exists', 409);

            $pdo->prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
                ->execute([$username, password_hash($password, PASSWORD_BCRYPT)]);
            
            http_response_code(201);
            echo json_encode(['message' => 'User created']);
            break;

        case 'login':
            $username = $input['username'] ?? '';
            $password = $input['password'] ?? '';
            Validator::username($username);
            Validator::password($password);

            $stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE username = ?');
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if (!$user || !password_verify($password, $user['password_hash'])) {
                throw new RuntimeException('Invalid credentials', 401);
            }

            echo json_encode(['token' => JWT::encode([
                'sub' => $user['id'],
                'exp' => time() + JWT_EXPIRATION
            ], getenv('JWT_SECRET'))]);
            break;

        case 'store_token':
            $token = $input['token'] ?? '';
            Validator::fcmToken($token);

            try {
                $pdo->prepare('INSERT INTO fcm_tokens (token) VALUES (?)')->execute([$token]);
                echo json_encode(['message' => 'Token stored']);
            } catch (PDOException $e) {
                if ($e->errorInfo[1] === 1062) throw new RuntimeException('Token exists', 409);
                throw new RuntimeException('Database error', 500);
            }
            break;

        case 'send_notification':
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if (!preg_match('/Bearer\s+(.+)$/i', $authHeader, $matches)) {
                throw new RuntimeException('Missing token', 401);
            }
            if (!JWT::decode($matches[1], getenv('JWT_SECRET'))) {
                throw new RuntimeException('Invalid token', 401);
            }

            $title = trim($input['title'] ?? '');
            $body = trim($input['body'] ?? '');
            Validator::notificationContent($title, $body);

            $tokens = $pdo->query('SELECT token FROM fcm_tokens')->fetchAll(PDO::FETCH_COLUMN);
            if (empty($tokens)) throw new RuntimeException('No tokens available', 404);

            $result = FirebaseService::sendNotifications($title, $body, $tokens);
            echo json_encode([
                'message' => 'Notifications sent',
                'success_count' => $result['success'],
                'failure_count' => $result['failure']
            ]);
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
    error_log('Critical: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Internal Server Error', 'code' => 500]);
}