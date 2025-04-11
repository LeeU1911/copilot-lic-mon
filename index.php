<?php
require 'vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Initialize session with secure settings
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => true, // Set to true in production with HTTPS
    'cookie_samesite' => 'Lax',
    'use_strict_mode' => true
]);

// Set secure headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https://github.com https://api.github.com https://js.stripe.com; script-src 'self' https://js.stripe.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;");

// Generate CSRF token if not exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Database connection with improved error handling
try {
    $db = new SQLite3('db.sqlite');
    $db->enableExceptions(true);
    
    // Set secure pragmas
    $db->exec('PRAGMA foreign_keys = ON');
    $db->exec('PRAGMA journal_mode = WAL');
} catch (Exception $e) {
    error_log('Database connection error: ' . $e->getMessage());
    http_response_code(500);
    exit('Database connection error');
}

// Create tables with improved schema
try {
    $db->exec("CREATE TABLE IF NOT EXISTS github_auth (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_token TEXT NOT NULL,
        github_org TEXT NOT NULL UNIQUE,
        session_id TEXT NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_org TEXT NOT NULL UNIQUE,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        status TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (github_org) REFERENCES github_auth(github_org) ON DELETE CASCADE
    )");

    // Add indexes for performance
    $db->exec("CREATE INDEX IF NOT EXISTS idx_github_auth_org ON github_auth(github_org)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_subscriptions_org ON subscriptions(github_org)");
} catch (Exception $e) {
    error_log('Database schema error: ' . $e->getMessage());
    http_response_code(500);
    exit('Database schema error');
}

// Use environment variables for sensitive data
$clientId = $_ENV['GITHUB_CLIENT_ID'] ?? '';
$clientSecret = $_ENV['GITHUB_CLIENT_SECRET'] ?? '';
$redirectUri = $_ENV['REDIRECT_URI'] ?? '';

// Validate and sanitize redirect URI
if (!filter_var($redirectUri, FILTER_VALIDATE_URL)) {
    error_log('Invalid redirect URI configured');
    http_response_code(500);
    exit('Configuration error: Invalid redirect URI');
}

// Check for missing environment variables
$missingVars = [];
if (empty($clientId)) $missingVars[] = 'GITHUB_CLIENT_ID';
if (empty($clientSecret)) $missingVars[] = 'GITHUB_CLIENT_SECRET';
if (empty($redirectUri)) $missingVars[] = 'REDIRECT_URI';

if (!empty($missingVars)) {
    error_log('Missing required environment variables: ' . implode(', ', $missingVars));
    http_response_code(500);
    exit('Configuration error: Missing required environment variables: ' . implode(', ', $missingVars));
}

// Handle logout request with proper authentication
if (isset($_GET['logout']) && isset($_SESSION['user_id'])) {
    try {
        // Verify CSRF token for logout
        if (!isset($_GET['csrf_token']) || $_GET['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception('CSRF token validation failed');
        }

        // Get current session ID before destroying it
        $currentSessionId = session_id();

        // Clear session first
        session_unset();
        session_destroy();

        // Then delete from database
        $stmt = $db->prepare("DELETE FROM github_auth WHERE session_id = :session_id");
        $stmt->bindValue(':session_id', $currentSessionId, SQLITE3_TEXT);
        $result = $stmt->execute();
        
        if ($result === false) {
            error_log('Failed to delete session from database');
            // Continue with redirect even if database deletion fails
        }
        
        // Redirect to login page
        header("Location: $redirectUri");
        exit;
    } catch (Exception $e) {
        error_log('Logout error: ' . $e->getMessage());
        // Clear session even if there's an error
        session_unset();
        session_destroy();
        header("Location: $redirectUri?logout_error=1");
        exit;
    }
}

// Step 1: GitHub redirects back with ?code
if (isset($_GET['code'])) {
    $code = htmlspecialchars($_GET['code'], ENT_QUOTES, 'UTF-8');
    
    try {
        // Validate state parameter (should be implemented for OAuth security)
        if (!isset($_GET['state']) || $_GET['state'] !== $_SESSION['oauth_state']) {
            throw new Exception('Invalid OAuth state');
        }
        
        // Validate code parameter
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $code)) {
            throw new Exception('Invalid code parameter');
        }
        
        $ch = curl_init('https://github.com/login/oauth/access_token');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_POSTFIELDS => http_build_query([
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'code' => $code,
                'redirect_uri' => $redirectUri
            ]),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2
        ]);
        
        $response = curl_exec($ch);
        if ($response === false) {
            throw new Exception('GitHub API request failed: ' . curl_error($ch));
        }
        
        $res = json_decode($response, true);
        curl_close($ch);

        if (!empty($res['access_token'])) {
            $token = $res['access_token'];

            // Get user's orgs with proper error handling
            $ch = curl_init('https://api.github.com/user/orgs');
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => [
                    'Authorization: Bearer ' . $token,
                    'User-Agent: CopilotAuditApp',
                    'Accept: application/vnd.github+json'
                ],
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2
            ]);
            
            $response = curl_exec($ch);
            if ($response === false) {
                throw new Exception('GitHub organizations request failed: ' . curl_error($ch));
            }
            
            $orgs = json_decode($response, true);
            curl_close($ch);

            if (!empty($orgs)) {
                $org = $orgs[0]['login'];

                // Validate organization name
                if (!preg_match('/^[a-zA-Z0-9-]+$/', $org)) {
                    throw new Exception('Invalid organization name');
                }

                // Store in database with session ID for authentication
                $stmt = $db->prepare("INSERT OR REPLACE INTO github_auth (github_token, github_org, session_id) VALUES (:token, :org, :session_id)");
                $stmt->bindValue(':token', $token, SQLITE3_TEXT);
                $stmt->bindValue(':org', $org, SQLITE3_TEXT);
                $stmt->bindValue(':session_id', session_id(), SQLITE3_TEXT);
                $stmt->execute();
                
                // Set user session
                $_SESSION['user_id'] = $org;
                $_SESSION['last_activity'] = time();

                // Regenerate session ID to prevent session fixation
                session_regenerate_id(true);

                // Update the session ID in the database after regeneration
                $newSessionId = session_id();
                $stmt = $db->prepare("UPDATE github_auth SET session_id = :new_session_id WHERE github_org = :org");
                $stmt->bindValue(':new_session_id', $newSessionId, SQLITE3_TEXT);
                $stmt->bindValue(':org', $org, SQLITE3_TEXT);
                $stmt->execute();

                header("Location: $redirectUri");
                exit;
            } else {
                throw new Exception('No GitHub organizations found');
            }
        } else {
            throw new Exception('Failed to get GitHub token: ' . ($res['error_description'] ?? 'Unknown error'));
        }
    } catch (Exception $e) {
        error_log('GitHub OAuth error: ' . $e->getMessage());
        http_response_code(400);
        exit('GitHub authentication failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
    }
}

// Generate a new state parameter for OAuth
$_SESSION['oauth_state'] = bin2hex(random_bytes(16));

// Step 2: If authenticated, call Copilot seats API
$auth = null;
if (isset($_SESSION['user_id'])) {
    try {
        // Check session timeout (30 minutes)
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
            session_unset();
            session_destroy();
            header("Location: $redirectUri?session_expired=1");
            exit;
        }
        $_SESSION['last_activity'] = time();

        // Get the current session ID
        $currentSessionId = session_id();
        
        // Query the database with the current session ID
        $stmt = $db->prepare("SELECT github_token, github_org FROM github_auth WHERE session_id = :session_id");
        $stmt->bindValue(':session_id', $currentSessionId, SQLITE3_TEXT);
        $result = $stmt->execute();
        $auth = $result->fetchArray(SQLITE3_ASSOC);

        if (!$auth) {
            // If no auth found, clear the session and redirect to login
            session_unset();
            session_destroy();
            header("Location: $redirectUri?session_invalid=1");
            exit;
        }
    } catch (Exception $e) {
        error_log('Auth query error: ' . $e->getMessage());
        session_unset();
        session_destroy();
        header("Location: $redirectUri?auth_error=1");
        exit;
    }
}

$seats = [];
$inactiveSeats = [];
$totalPotentialSavings = 0;
$org = '';

if ($auth) {
    try {
        $token = $auth['github_token'];
        $org = htmlspecialchars($auth['github_org']);

        $ch = curl_init("https://api.github.com/orgs/$org/copilot/billing/seats");
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                "Authorization: Bearer $token",
                "User-Agent: CopilotAuditApp",
                "Accept: application/vnd.github+json"
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($response === false) {
            throw new Exception('Copilot API request failed: ' . curl_error($ch));
        }
        
        if ($httpCode !== 200) {
            throw new Exception('Copilot API error: HTTP code ' . $httpCode);
        }
        
        $seats = json_decode($response, true);
        curl_close($ch);

        // Calculate potential savings
        $monthlyCostPerSeat = 19; // GitHub Copilot Business cost per seat per month
        
        if (isset($seats['seats']) && is_array($seats['seats'])) {
            foreach ($seats['seats'] as $seat) {
                $isInactive = false;
                $daysInactive = null;
                
                if (empty($seat['last_activity_at'])) {
                    $isInactive = true;
                    $daysInactive = 'Never';
                } else {
                    $lastActive = new DateTime($seat['last_activity_at']);
                    $now = new DateTime();
                    $daysInactive = $now->diff($lastActive)->days;
                    
                    if ($daysInactive > 90) {
                        $isInactive = true;
                    }
                }
                
                if ($isInactive) {
                    $inactiveSeats[] = [
                        'login' => $seat['assignee']['login'],
                        'last_active' => $seat['last_activity_at'] ?? 'Never',
                        'days_inactive' => $daysInactive,
                        'potential_savings' => $monthlyCostPerSeat
                    ];
                    $totalPotentialSavings += $monthlyCostPerSeat;
                }
            }
        }
    } catch (Exception $e) {
        error_log('GitHub API error: ' . $e->getMessage());
        $apiError = htmlspecialchars($e->getMessage());
    }

    // Check subscription status
    try {
        $stmt = $db->prepare("SELECT * FROM subscriptions WHERE github_org = :org");
        $stmt->bindValue(':org', $org, SQLITE3_TEXT);
        $result = $stmt->execute();
        $subscription = $result->fetchArray(SQLITE3_ASSOC);
        $isSubscribed = $subscription && $subscription['status'] === 'active';
    } catch (Exception $e) {
        error_log('Subscription query error: ' . $e->getMessage());
        $isSubscribed = false;
    }
}

// Handle Stripe webhook with improved security
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SERVER['HTTP_STRIPE_SIGNATURE'])) {
    try {
        // Get the raw POST data
        $payload = @file_get_contents('php://input');
        if ($payload === false) {
            throw new Exception('Failed to read POST data');
        }
        
        $sig_header = $_SERVER['HTTP_STRIPE_SIGNATURE'];
        $webhookSecret = $_ENV['STRIPE_WEBHOOK_SECRET'] ?? '';
        
        if (empty($webhookSecret)) {
            throw new Exception('Webhook secret is not configured');
        }
        
        \Stripe\Stripe::setApiKey($_ENV['STRIPE_SECRET_KEY'] ?? '');
        $event = \Stripe\Webhook::constructEvent($payload, $sig_header, $webhookSecret);

        if ($event->type === 'checkout.session.completed') {
            $session = $event->data->object;
            $customerId = $session->customer;
            $subscriptionId = $session->subscription;
            
            // Validate metadata
            if (!isset($session->metadata->github_org) || empty($session->metadata->github_org)) {
                throw new Exception('Missing github_org in webhook metadata');
            }
            
            $githubOrg = $session->metadata->github_org;

            // Validate organization name
            if (!preg_match('/^[a-zA-Z0-9-]+$/', $githubOrg)) {
                throw new Exception('Invalid organization name in webhook metadata');
            }
            
            // Log and update subscription
            $stmt = $db->prepare("INSERT OR REPLACE INTO subscriptions 
                (github_org, stripe_customer_id, stripe_subscription_id, status, updated_at) 
                VALUES (:org, :customer_id, :subscription_id, 'active', CURRENT_TIMESTAMP)");
                
            $stmt->bindValue(':org', $githubOrg, SQLITE3_TEXT);
            $stmt->bindValue(':customer_id', $customerId, SQLITE3_TEXT);
            $stmt->bindValue(':subscription_id', $subscriptionId, SQLITE3_TEXT);
            $stmt->execute();
        }

        http_response_code(200);
        exit('Webhook processed successfully');
    } catch (\Stripe\Exception\SignatureVerificationException $e) {
        error_log('Stripe webhook signature error: ' . $e->getMessage());
        http_response_code(400);
        exit('Invalid signature');
    } catch (Exception $e) {
        error_log('Stripe webhook error: ' . $e->getMessage());
        http_response_code(400);
        exit('Webhook error');
    }
}

// Handle subscription creation with CSRF protection
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['subscribe'])) {
    try {
        // Verify CSRF token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception('CSRF token validation failed');
        }
        
        if (!isset($_SESSION['user_id'])) {
            throw new Exception('User authentication required');
        }
        
        $stripeKey = $_ENV['STRIPE_SECRET_KEY'] ?? '';
        $stripePriceId = $_ENV['STRIPE_PRICE_ID'] ?? '';
        
        if (empty($stripeKey) || empty($stripePriceId)) {
            throw new Exception('Stripe configuration missing');
        }
        
        \Stripe\Stripe::setApiKey($stripeKey);
        
        $checkout_session = \Stripe\Checkout\Session::create([
            'payment_method_types' => ['card'],
            'line_items' => [[
                'price' => $stripePriceId,
                'quantity' => 1,
            ]],
            'mode' => 'subscription',
            'success_url' => $redirectUri . '?success=1',
            'cancel_url' => $redirectUri . '?canceled=1',
            'metadata' => [
                'github_org' => $org
            ],
        ]);

        header("Location: " . $checkout_session->url);
        exit();
    } catch (Exception $e) {
        error_log('Subscription creation error: ' . $e->getMessage());
        http_response_code(400);
        exit('Subscription creation failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Copilot License Monitoring</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://js.stripe.com/v3/"></script>
    <style>
        /* CSS remains the same */
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        h1 {
            color: #24292e;
            border-bottom: 2px solid #e1e4e8;
            padding-bottom: 10px;
        }
        h3 {
            color: #24292e;
        }
        .seats-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .seats-table th, .seats-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e1e4e8;
        }
        .seats-table th {
            background-color: #f6f8fa;
            font-weight: 600;
            color: #24292e;
        }
        .seats-table tr:hover {
            background-color: #f6f8fa;
        }
        .stats {
            background: #f6f8fa;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
        }
        a {
            color: #0366d6;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .logout {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #e1e4e8;
        }
        .savings-card {
            background: linear-gradient(135deg, #2ea44f 0%, #2c974b 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .savings-card h2 {
            margin: 0 0 10px 0;
            font-size: 24px;
        }
        
        .savings-amount {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .action-buttons {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        
        .btn {
            padding: 10px 20px;
            border-radius: 6px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: #2ea44f;
            color: white;
        }
        
        .btn-primary:hover {
            background: #2c974b;
        }
        
        .btn-secondary {
            background: white;
            color: #2ea44f;
            border: 2px solid #2ea44f;
        }
        
        .btn-secondary:hover {
            background: #f6f8fa;
        }
        
        .inactive-seats {
            margin-top: 30px;
        }
        
        .inactive-seats h3 {
            color: #cb2431;
            margin-bottom: 15px;
        }
        
        .seats-table td.warning {
            color: #cb2431;
        }
        
        .subscription-status {
            background: #f6f8fa;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .subscription-status.active {
            background: #e6f3ff;
            border-left: 4px solid #0366d6;
        }
        
        .subscription-status.inactive {
            background: #fff8c5;
            border-left: 4px solid #f9c513;
        }
        
        .subscription-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .subscription-badge.active {
            background: #0366d6;
            color: white;
        }
        
        .subscription-badge.inactive {
            background: #f9c513;
            color: #24292e;
        }

        .auto-save-status {
            display: inline-flex;
            align-items: center;
            background: rgba(255, 255, 255, 0.2);
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 500;
        }

        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e1e4e8;
            text-align: center;
            color: #6a737d;
        }

        .footer a {
            color: #0366d6;
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }
        
        .error-message {
            background: #ffebe9;
            border-left: 4px solid #cb2431;
            padding: 15px;
            margin: 20px 0;
            border-radius: 6px;
        }
    </style>
</head>
<body>
    <h1>Copilot License Monitoring</h1>

    <?php if (isset($apiError)): ?>
        <div class="error-message">
            <strong>API Error:</strong> <?= $apiError ?>
        </div>
    <?php endif; ?>

    <?php if (!isset($_SESSION['user_id'])): ?>
        <a href="https://github.com/login/oauth/authorize?client_id=<?= htmlspecialchars($clientId) ?>&redirect_uri=<?= urlencode($redirectUri) ?>&scope=read:org,manage_billing:copilot&state=<?= htmlspecialchars($_SESSION['oauth_state']) ?>">
            Login with GitHub
        </a>
    <?php else: ?>
        <h3>Organization: <?= htmlspecialchars($org) ?></h3>
        
        <?php if (isset($_GET['success'])): ?>
            <div class="subscription-status active">
                <div>
                    <strong>Thank you for subscribing!</strong>
                    <p>Your subscription is now active. You'll receive automatic savings reports.</p>
                </div>
                <span class="subscription-badge active">Active</span>
            </div>
        <?php elseif (isset($_GET['canceled'])): ?>
            <div class="subscription-status inactive">
                <div>
                    <strong>Subscription canceled</strong>
                    <p>You can try subscribing again when you're ready.</p>
                </div>
                <span class="subscription-badge inactive">Inactive</span>
            </div>
        <?php else: ?>
            <div class="subscription-status <?= isset($isSubscribed) && $isSubscribed ? 'active' : 'inactive' ?>">
                <div>
                    <strong><?= isset($isSubscribed) && $isSubscribed ? 'Premium Subscription Active' : 'Free Version' ?></strong>
                    <p><?= isset($isSubscribed) && $isSubscribed ? 'You\'re receiving automatic savings reports.' : 'Upgrade to get automatic savings reports and more features.' ?></p>
                </div>
                <span class="subscription-badge <?= isset($isSubscribed) && $isSubscribed ? 'active' : 'inactive' ?>">
                    <?= isset($isSubscribed) && $isSubscribed ? 'Active' : 'Free' ?>
                </span>
            </div>
        <?php endif; ?>

        <?php if (!empty($seats) && isset($seats['total_seats'])): ?>
            <div class="stats">
                <strong>Total Seats:</strong> <?= (int)$seats['total_seats'] ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($inactiveSeats)): ?>
            <div class="savings-card">
                <h2>Potential Monthly Savings</h2>
                <div class="savings-amount">$<?= number_format($totalPotentialSavings, 2) ?></div>
                <p>You could save this amount by removing <?= count($inactiveSeats) ?> inactive seats</p>
                <div class="action-buttons">
                    <?php if (isset($isSubscribed) && $isSubscribed): ?>
                        <div class="auto-save-status">
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style="margin-right: 8px;">
                                <path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0z"/>
                            </svg>
                            Auto-save feature is active
                        </div>
                    <?php else: ?>
                        <a href="#" class="btn btn-primary" onclick="alert('Save functionality coming soon!')">
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                <path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0z"/>
                            </svg>
                            Save Now
                        </a>
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="subscribe" value="1">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <button type="submit" class="btn btn-secondary">
                                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                    <path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zm0 14.5a6.5 6.5 0 1 1 0-13 6.5 6.5 0 0 1 0 13z"/>
                                    <path d="M8 4a.75.75 0 0 1 .75.75v3.5h3.5a.75.75 0 0 1 0 1.5h-3.5v3.5a.75.75 0 0 1-1.5 0v-3.5h-3.5a.75.75 0 0 1 0-1.5h3.5v-3.5A.75.75 0 0 1 8 4z"/>
                                </svg>
                                Subscribe for Auto-Save
                            </button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>

            <div class="inactive-seats">
                <h3>Inactive Seats (>90 days)</h3>
                <table class="seats-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Last Active</th>
                            <th>Days Inactive</th>
                            <th>Monthly Savings</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($inactiveSeats as $seat): ?>
                            <tr>
                                <td class="warning"><?= htmlspecialchars($seat['login']) ?></td>
                                <td><?= htmlspecialchars($seat['last_active']) ?></td>
                                <td><?= htmlspecialchars($seat['days_inactive']) ?></td>
                                <td>$<?= number_format($seat['potential_savings'], 2) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <?php if (!empty($seats) && isset($seats['seats'])): ?>
            <h3>All Seats</h3>
            <table class="seats-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Last Active</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($seats['seats'] as $seat): ?>
                        <tr>
                            <td><?= htmlspecialchars($seat['assignee']['login']) ?></td>
                            <td><?= htmlspecialchars($seat['last_activity_at'] ?? 'N/A') ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    <?php endif; ?>

    <?php if (isset($_SESSION['user_id'])): ?>
        <div class="logout">
            <a href="<?= htmlspecialchars($redirectUri) ?>?logout=1&csrf_token=<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">Log out</a>
        </div>
    <?php endif; ?>

    <div class="footer">
        <a href="privacy.php">Privacy Policy</a>
    </div>

</body>
</html>
