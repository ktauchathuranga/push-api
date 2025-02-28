<?php
// Error reporting for production
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/api.log');

header('Content-Type: application/json');

// JWT Helper Functions
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/'));
}

function generate_jwt($payload, $secret) {
    $header = base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = base64url_encode(json_encode($payload));
    $signature = hash_hmac('sha256', "$header.$payload", $secret, true);
    return "$header.$payload." . base64url_encode($signature);
}

function verify_jwt($token, $secret) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;
    [$header, $payload, $signature] = $parts;
    $expected_signature = hash_hmac('sha256', "$header.$payload", $secret, true);
    $payload_data = json_decode(base64url_decode($payload), true);
    return hash_equals(base64url_decode($signature), $expected_signature) && 
           ($payload_data['exp'] ?? 0) > time();
}

// Database Connection
function get_db_connection() {
    $dsn = "mysql:host=" . getenv('DB_HOST') . ";dbname=" . getenv('DB_NAME') . ";charset=utf8mb4";
    return new PDO($dsn, getenv('DB_USER'), getenv('DB_PASS'), [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
}

// Main API Handler
try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Method Not Allowed', 405);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $action = $input['action'] ?? '';

    switch ($action) {
        case 'signup':
            // Validate input
            if (empty($input['username']) || empty($input['password']) || strlen($input['password']) < 6) {
                throw new Exception('Invalid username or password (minimum 6 characters)', 400);
            }

            $pdo = get_db_connection();
            
            // Check existing user
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$input['username']]);
            if ($stmt->fetch()) {
                throw new Exception('Username already exists', 409);
            }

            // Create user
            $password_hash = password_hash($input['password'], PASSWORD_DEFAULT);
            $pdo->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
                ->execute([$input['username'], $password_hash]);

            echo json_encode(['message' => 'User created successfully']);
            break;

        case 'login':
            // Validate input
            if (empty($input['username']) || empty($input['password'])) {
                throw new Exception('Missing username or password', 400);
            }

            $pdo = get_db_connection();
            
            // Find user
            $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE username = ?");
            $stmt->execute([$input['username']]);
            $user = $stmt->fetch();

            if (!$user || !password_verify($input['password'], $user['password_hash'])) {
                throw new Exception('Invalid credentials', 401);
            }

            // Generate JWT
            $token = generate_jwt(
                ['sub' => $user['id'], 'exp' => time() + 3600],
                getenv('JWT_SECRET')
            );
            echo json_encode(['token' => $token]);
            break;

        case 'store_token':
            // Validate input
            if (empty($input['token']) || !is_string($input['token'])) {
                throw new Exception('Invalid or missing FCM token', 400);
            }

            $pdo = get_db_connection();
            
            try {
                $pdo->prepare("INSERT INTO fcm_tokens (token) VALUES (?)")
                    ->execute([$input['token']]);
                echo json_encode(['message' => 'FCM token stored successfully']);
            } catch (PDOException $e) {
                if ($e->getCode() === '23000') {
                    throw new Exception('Token already exists', 409);
                }
                throw new Exception('Database error', 500);
            }
            break;

        case 'send_notification':
            // Verify JWT
            $headers = getallheaders();
            if (!preg_match('/Bearer (.+)/', $headers['Authorization'] ?? '', $matches) || 
                !verify_jwt($matches[1], getenv('JWT_SECRET'))) {
                throw new Exception('Unauthorized', 401);
            }

            // Validate input
            if (empty($input['title']) || empty($input['body'])) {
                throw new Exception('Missing notification title or body', 400);
            }

            // Get Firebase access token
            $service_account = json_decode(file_get_contents(__DIR__ . '/service-account.json'), true);
            if (!$service_account) throw new Exception('Invalid service account', 500);

            $jwt_header = base64url_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
            $jwt_payload = base64url_encode(json_encode([
                'iss' => $service_account['client_email'],
                'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
                'aud' => 'https://oauth2.googleapis.com/token',
                'exp' => time() + 3600,
                'iat' => time()
            ]));
            
            openssl_sign("$jwt_header.$jwt_payload", $signature, $service_account['private_key'], 'sha256');
            $jwt = "$jwt_header.$jwt_payload." . base64url_encode($signature);

            // Get OAuth token
            $ch = curl_init('https://oauth2.googleapis.com/token');
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query([
                    'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                    'assertion' => $jwt
                ]),
                CURLOPT_RETURNTRANSFER => true
            ]);
            $token_response = json_decode(curl_exec($ch), true);
            curl_close($ch);
            
            if (empty($token_response['access_token'])) {
                throw new Exception('Failed to obtain access token', 500);
            }

            // Get all FCM tokens
            $pdo = get_db_connection();
            $tokens = $pdo->query("SELECT token FROM fcm_tokens")->fetchAll(PDO::FETCH_COLUMN, 0);

            // Send notifications
            $project_id = $service_account['project_id'];
            $url = "https://fcm.googleapis.com/v1/projects/$project_id/messages:send";
            $headers = [
                'Authorization: Bearer ' . $token_response['access_token'],
                'Content-Type: application/json'
            ];

            $success = 0;
            foreach ($tokens as $token) {
                $data = [
                    'message' => [
                        'token' => $token,
                        'notification' => [
                            'title' => $input['title'],
                            'body' => $input['body']
                        ]
                    ]
                ];

                $ch = curl_init($url);
                curl_setopt_array($ch, [
                    CURLOPT_POST => true,
                    CURLOPT_HTTPHEADER => $headers,
                    CURLOPT_POSTFIELDS => json_encode($data),
                    CURLOPT_RETURNTRANSFER => true
                ]);
                $response = curl_exec($ch);
                if (curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200) $success++;
                curl_close($ch);
            }

            echo json_encode([
                'message' => 'Notifications sent',
                'success_count' => $success,
                'failure_count' => count($tokens) - $success
            ]);
            break;

        default:
            throw new Exception('Invalid action', 404);
    }
} catch (Exception $e) {
    $code = $e->getCode() ?: 500;
    http_response_code($code);
    echo json_encode([
        'error' => $e->getMessage(),
        'code' => $code
    ]);
    error_log("[$code] " . $e->getMessage());
}