<?php
// Error reporting for production (logs errors, hides from output)
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/www/html/logs/api.log');

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
           $payload_data['exp'] > time();
}

// Database Connection
function get_db_connection() {
    $dsn = "mysql:host=" . getenv('DB_HOST') . ";dbname=" . getenv('DB_NAME') . ";charset=utf8mb4";
    return new PDO($dsn, getenv('DB_USER'), getenv('DB_PASS'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
}

// Signup Endpoint: /signup
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/signup') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (empty($input['username']) || empty($input['password']) || strlen($input['password']) < 6) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid username or password (min 6 chars)']);
        exit;
    }

    try {
        $pdo = get_db_connection();
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username");
        $stmt->execute(['username' => $input['username']]);
        if ($stmt->fetch()) {
            http_response_code(409);
            echo json_encode(['error' => 'Username already exists']);
            exit;
        }

        $password_hash = password_hash($input['password'], PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (username, password_hash) VALUES (:username, :password_hash)");
        $stmt->execute(['username' => $input['username'], 'password_hash' => $password_hash]);
        echo json_encode(['message' => 'User created successfully']);
    } catch (Exception $e) {
        error_log("Signup error: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Internal server error']);
    }
    exit;
}

// Login Endpoint: /login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/login') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (empty($input['username']) || empty($input['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing username or password']);
        exit;
    }

    try {
        $pdo = get_db_connection();
        $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE username = :username");
        $stmt->execute(['username' => $input['username']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($input['password'], $user['password_hash'])) {
            $payload = ['sub' => $user['id'], 'exp' => time() + 3600]; // 1-hour expiry
            $token = generate_jwt($payload, getenv('JWT_SECRET'));
            echo json_encode(['token' => $token]);
        } else {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials']);
        }
    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Internal server error']);
    }
    exit;
}

// Save FCM Token Endpoint: /store-token
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/store-token') {
    // Get the JSON input
    $input = json_decode(file_get_contents('php://input'), true);

    // Validate the token
    if (empty($input['token']) || !is_string($input['token'])) {
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Invalid or missing token']);
        exit;
    }

    // Store the token in the database
    try {
        $pdo = get_db_connection(); // Assume this function returns a PDO connection
        $stmt = $pdo->prepare("INSERT INTO fcm_tokens (token) VALUES (:token)");
        $stmt->execute(['token' => $input['token']]);
        echo json_encode(['message' => 'FCM token saved successfully']);
    } catch (PDOException $e) {
        if ($e->getCode() == 23000) { // Duplicate entry error
            http_response_code(409); // Conflict
            echo json_encode(['error' => 'Token already exists']);
        } else {
            error_log("Save token error: " . $e->getMessage()); // Log the error for debugging
            http_response_code(500); // Internal Server Error
            echo json_encode(['error' => 'Internal server error']);
        }
    }
    exit;
}

// Send Notification Endpoint: /send-notification
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/send-notification') {
    // Verify JWT
    $headers = getallheaders();
    $auth = $headers['Authorization'] ?? '';
    if (!preg_match('/Bearer (.+)/', $auth, $matches) || !verify_jwt($matches[1], getenv('JWT_SECRET'))) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }

    // Validate input
    $input = json_decode(file_get_contents('php://input'), true);
    if (empty($input['title']) || empty($input['body'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing title or body']);
        exit;
    }

    // Load Firebase service account
    $service_account = json_decode(file_get_contents('/app/service-account.json'), true);
    if (!$service_account) {
        http_response_code(500);
        echo json_encode(['error' => 'Invalid service account']);
        exit;
    }

    // Generate Google OAuth JWT
    $jwt_payload = [
        'iss' => $service_account['client_email'],
        'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
        'aud' => 'https://oauth2.googleapis.com/token',
        'exp' => time() + 3600,
        'iat' => time()
    ];
    $jwt_header = base64url_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
    $jwt_payload_encoded = base64url_encode(json_encode($jwt_payload));
    openssl_sign("$jwt_header.$jwt_payload_encoded", $signature, $service_account['private_key'], 'sha256WithRSAEncryption');
    $jwt = "$jwt_header.$jwt_payload_encoded." . base64url_encode($signature);

    // Get OAuth token
    $ch = curl_init('https://oauth2.googleapis.com/token');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion' => $jwt]),
        CURLOPT_RETURNTRANSFER => true
    ]);
    $token_response = json_decode(curl_exec($ch), true);
    curl_close($ch);
    $access_token = $token_response['access_token'] ?? null;
    if (!$access_token) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to obtain access token']);
        exit;
    }

    // Fetch FCM tokens
    try {
        $pdo = get_db_connection();
        $tokens = $pdo->query("SELECT token FROM fcm_tokens")->fetchAll(PDO::FETCH_COLUMN);
    } catch (Exception $e) {
        error_log("DB error: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Database error']);
        exit;
    }

    // Send notifications
    $url = "https://fcm.googleapis.com/v1/projects/{$service_account['project_id']}/messages:send";
    $headers = ["Authorization: Bearer $access_token", "Content-Type: application/json"];
    $success = 0;
    $failure = 0;

    foreach ($tokens as $token) {
        $message = [
            'message' => [
                'token' => $token,
                'notification' => ['title' => $input['title'], 'body' => $input['body']]
            ]
        ];
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_POSTFIELDS => json_encode($message),
            CURLOPT_RETURNTRANSFER => true
        ]);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $http_code === 200 ? $success++ : $failure++;
    }

    echo json_encode(['message' => 'Notifications sent', 'success_count' => $success, 'failure_count' => $failure]);
    exit;
}

// Handle invalid endpoints
http_response_code(404);
echo json_encode(['error' => 'Endpoint not found']);