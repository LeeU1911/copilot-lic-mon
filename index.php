<?php
// Simple dotenv implementation
function loadEnv($path) {
    if (!file_exists($path)) {
        return false;
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '=') !== false && strpos($line, '#') !== 0) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            if (!array_key_exists($key, $_ENV)) {
                putenv(sprintf('%s=%s', $key, $value));
                $_ENV[$key] = $value;
            }
        }
    }
    return true;
}

// Load environment variables
loadEnv(__DIR__ . '/.env');

// Include Stripe PHP library
require_once __DIR__ . '/stripe-php/init.php';


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
header("Content-Security-Policy: default-src 'self' https://github.com https://api.github.com https://js.stripe.com; script-src 'self' https://js.stripe.com https://cloud.umami.is; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.stripe.com;");

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
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS payment (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_org TEXT NOT NULL UNIQUE,
        stripe_customer_email TEXT,
        stripe_session_id TEXT,
        stripe_payment_intent TEXT,
        status TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    $db->exec("CREATE TABLE IF NOT EXISTS gh_api_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_org TEXT NOT NULL,
        user_id TEXT NOT NULL,
        payment_id TEXT NOT NULL,
        savings_amount REAL NOT NULL,
        seats_disabled INTEGER NOT NULL,
        total_inactive_seats INTEGER NOT NULL,
        request TEXT,
        response TEXT,
        errors TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Add indexes for performance
    $db->exec("CREATE INDEX IF NOT EXISTS idx_github_auth_org ON github_auth(github_org)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_github_auth_user ON github_auth(user_id)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_payment_org ON payment(github_org)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_seat_disabling_logs_org ON gh_api_audit_logs(github_org)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_seat_disabling_logs_user ON gh_api_audit_logs(user_id)");
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
            // Get the authenticated user
            $ch = curl_init('https://api.github.com/user');
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
                throw new Exception('GitHub user request failed: ' . curl_error($ch));
            }
            
            $user = json_decode($response, true);
            curl_close($ch);

            $userId = $user['login'];

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
                $stmt = $db->prepare("INSERT OR REPLACE INTO github_auth (github_token, github_org, user_id, session_id) VALUES (:token, :org, :user_id, :session_id)");
                $stmt->bindValue(':token', $token, SQLITE3_TEXT);
                $stmt->bindValue(':org', $org, SQLITE3_TEXT);
                $stmt->bindValue(':user_id', $userId, SQLITE3_TEXT);
                $stmt->bindValue(':session_id', session_id(), SQLITE3_TEXT);
                $stmt->execute();
                
                // Set user session
                $_SESSION['user_id'] = $userId;
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
        // Check session timeout (30 days)
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 60 * 60 * 24 * 30)) {
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
$paid = false;
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
                        'login' => $paid ? $seat['assignee']['login'] : '******' . substr($seat['assignee']['login'], -1), // mask username value until user pays
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

    // Check payment status
    try {
        $stmt = $db->prepare("SELECT * FROM payment WHERE github_org = :org");
        $stmt->bindValue(':org', $org, SQLITE3_TEXT);
        $result = $stmt->execute();
        $payment = $result->fetchArray(SQLITE3_ASSOC);
        $paid = $payment && $payment['status'] === 'active';
    } catch (Exception $e) {
        error_log('payment query error: ' . $e->getMessage());
        $paid = false;
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
            $customerEmail = $session->customer_details->email;
            $sessionId = $session->id;
            $paymentIntent = $session->payment_intent;
            
            // Validate metadata
            if (!isset($session->metadata->github_org) || empty($session->metadata->github_org)) {
                throw new Exception('Missing github_org in webhook metadata');
            }
            
            $githubOrg = $session->metadata->github_org;

            // Validate organization name
            if (!preg_match('/^[a-zA-Z0-9-]+$/', $githubOrg)) {
                throw new Exception('Invalid organization name in webhook metadata');
            }
            
            // Log and update payment
            $stmt = $db->prepare("INSERT OR REPLACE INTO payment 
                (github_org, stripe_customer_email, stripe_session_id, stripe_payment_intent, status, updated_at) 
                VALUES (:org, :customer_email, :session_id, :payment_intent, 'active', CURRENT_TIMESTAMP)");
                
            $stmt->bindValue(':org', $githubOrg, SQLITE3_TEXT);
            $stmt->bindValue(':customer_email', $customerEmail, SQLITE3_TEXT);
            $stmt->bindValue(':session_id', $sessionId, SQLITE3_TEXT);
            $stmt->bindValue(':payment_intent', $paymentIntent, SQLITE3_TEXT);
            $stmt->execute();
        }
        
        // Handle checkout.session.completed for "Save Now" payments
        if ($event->type === 'checkout.session.completed') {
            $paymentIntent = $event->data->object;
            
            // Get the checkout session that created this payment intent
            $checkoutSessionId = $paymentIntent->id ?? null;
            if (!$checkoutSessionId) {
                throw new Exception('Missing checkout_session_id in payment intent metadata');
            }
            
            $checkoutSession = \Stripe\Checkout\Session::retrieve($checkoutSessionId);
            
            // Check if this is a "Save Now" payment
            if (isset($checkoutSession->metadata->savings_amount) && isset($checkoutSession->metadata->github_org)) {
                $githubOrg = $checkoutSession->metadata->github_org;
                $savingsAmount = $checkoutSession->metadata->savings_amount;
                
                error_log("Processing 'Save Now' payment for organization: $githubOrg with savings: $savingsAmount");
                
                // Get GitHub token for the organization
                $stmt = $db->prepare("SELECT github_token, user_id FROM github_auth WHERE github_org = :org");
                $stmt->bindValue(':org', $githubOrg, SQLITE3_TEXT);
                $result = $stmt->execute();
                $auth = $result->fetchArray(SQLITE3_ASSOC);
                
                if (!$auth || empty($auth['github_token'])) {
                    throw new Exception("GitHub token not found for organization: $githubOrg");
                }
                
                $githubToken = $auth['github_token'];
                $userId = $auth['user_id'];
                
                // Get inactive seats for the organization
                $inactiveSeats = [];
                $ch = curl_init("https://api.github.com/orgs/$githubOrg/copilot/billing/seats");
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_HTTPHEADER => [
                        "Authorization: Bearer $githubToken",
                        "User-Agent: CopilotAuditApp",
                        "Accept: application/vnd.github+json"
                    ],
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2
                ]);
                
                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                
                if ($response === false) {
                    throw new Exception('GitHub API request failed: ' . curl_error($ch));
                }
                
                if ($httpCode !== 200) {
                    throw new Exception('GitHub API error: HTTP code ' . $httpCode);
                }
                
                $seats = json_decode($response, true);
                curl_close($ch);
                
                // Find inactive seats
                if (isset($seats['seats']) && is_array($seats['seats'])) {
                    foreach ($seats['seats'] as $seat) {
                        $isInactive = false;
                        
                        if (empty($seat['last_activity_at'])) {
                            $isInactive = true;
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
                                'last_active' => $seat['last_activity_at'] ?? 'Never'
                            ];
                        }
                    }
                }
                
                // Disable inactive seats
                $disabledSeats = 0;
                $errors = [];
                
                foreach ($inactiveSeats as $seat) {
                    $username = $seat['login'];
                    $request = json_encode([
                            'selected_usernames' => [$username]
                        ]);
                    
                    // Call GitHub API to disable the seat
                    $ch = curl_init("https://api.github.com/orgs/$githubOrg/copilot/billing/selected_users");
                    curl_setopt_array($ch, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_CUSTOMREQUEST => "DELETE",
                        CURLOPT_HTTPHEADER => [
                            "Authorization: Bearer $githubToken",
                            "User-Agent: CopilotAuditApp",
                            "Accept: application/vnd.github+json"
                        ],
                        CURLOPT_POSTFIELDS => $request,
                        CURLOPT_SSL_VERIFYPEER => true,
                        CURLOPT_SSL_VERIFYHOST => 2
                    ]);
                    $response = curl_exec($ch);
                    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    curl_close($ch);
                    
                    if ($httpCode === 200) {
                        $disabledSeats++;
                        error_log("Successfully disabled Copilot seat for user: $username in organization: $githubOrg");
                    } else {
                        $errorMessage = "Failed to disable Copilot seat for user: $username in organization: $githubOrg. HTTP code: $httpCode";
                        
                        // Add specific error messages based on HTTP status code
                        switch ($httpCode) {
                            case 401:
                                $errorMessage .= " - Requires authentication. Please check your GitHub token.";
                                break;
                            case 403:
                                $errorMessage .= " - Forbidden. You don't have permission to manage Copilot seats.";
                                break;
                            case 404:
                                $errorMessage .= " - Resource not found. The user or organization may not exist.";
                                break;
                            case 422:
                                $errorMessage .= " - Copilot Business/Enterprise is not enabled, billing not set up, public code suggestions policy not set, seat management setting is set to enable Copilot for all users, or the seat was assigned via a team.";
                                break;
                            case 500:
                                $errorMessage .= " - Internal Server Error. GitHub's servers encountered an error.";
                                break;
                            default:
                                $errorMessage .= " - Unknown error occurred.";
                                break;
                        }
                        
                        error_log($errorMessage);
                        $errors[] = [
                            'username' => $username,
                            'error' => $errorMessage
                        ];
                    }
                }
                
                // Log the results
                error_log("Disabled $disabledSeats out of " . count($inactiveSeats) . " inactive seats for organization: $githubOrg");
                
                // Store the results in the database
                $stmt = $db->prepare("INSERT INTO gh_api_audit_logs 
                    (github_org, user_id, payment_id, savings_amount, seats_disabled, total_inactive_seats, request, response, errors, created_at) 
                    VALUES (:org, :user_id, :payment_id, :savings_amount, :seats_disabled, :total_inactive_seats, :request, :response, :errors, CURRENT_TIMESTAMP)");
                
                $stmt->bindValue(':org', $githubOrg, SQLITE3_TEXT);
                $stmt->bindValue(':user_id', $userId, SQLITE3_TEXT);
                $stmt->bindValue(':payment_id', $paymentIntent->id, SQLITE3_TEXT);
                $stmt->bindValue(':savings_amount', $savingsAmount, SQLITE3_FLOAT);
                $stmt->bindValue(':seats_disabled', $disabledSeats, SQLITE3_INTEGER);
                $stmt->bindValue(':total_inactive_seats', count($inactiveSeats), SQLITE3_INTEGER);
                $stmt->bindValue(':request', $request, SQLITE3_TEXT);
                $stmt->bindValue(':response', $response, SQLITE3_TEXT);
                $stmt->bindValue(':errors', !empty($errors) ? json_encode($errors) : null, SQLITE3_TEXT);
                $stmt->execute();
                
                // Return success response with detailed information
                $responseData = [
                    'success' => true,
                    'message' => "Successfully disabled $disabledSeats inactive seats",
                    'total_inactive_seats' => count($inactiveSeats),
                    'disabled_seats' => $disabledSeats,
                    'errors' => $errors
                ];
                
                // Store errors in session for display after redirect
                if (!empty($errors)) {
                    $_SESSION['seat_disabling_errors'] = $errors;
                }
                
                echo json_encode($responseData);
            }
        }

        http_response_code(200);
        exit('Webhook processed successfully');
    } catch (\Stripe\Exception\SignatureVerificationException $e) {
        error_log('Stripe webhook signature error: ' . $e->getMessage());
        http_response_code(400);
        exit('Invalid signature');
    } catch (Exception $e) {
        error_log('Stripe webhook error: ' . $e->getMessage());
        error_log('Stack trace: ' . $e->getTraceAsString());
        http_response_code(400);
        exit('Webhook error');
    }
}

// Handle "Save Now" with inline pricing
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_now'])) {
    try {
        // Debug information
        error_log('Save Now request received: ' . print_r($_POST, true));
        
        // Verify CSRF token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            error_log('CSRF token validation failed. Expected: ' . $_SESSION['csrf_token'] . ', Received: ' . ($_POST['csrf_token'] ?? 'not set'));
            throw new Exception('CSRF token validation failed');
        }
        
        if (!isset($_SESSION['user_id'])) {
            error_log('User authentication required but not set');
            throw new Exception('User authentication required');
        }
        
        // Validate savings and fee amounts
        $savingsAmount = isset($_POST['savings_amount']) ? floatval($_POST['savings_amount']) : 0;
        $feeAmount = isset($_POST['fee_amount']) ? floatval($_POST['fee_amount']) : 0;
        
        error_log('Savings amount: ' . $savingsAmount . ', Fee amount: ' . $feeAmount);
        
        if ($savingsAmount <= 0) {
            error_log('Invalid savings amount: ' . $savingsAmount);
            throw new Exception('Invalid savings amount');
        }
        
        if ($feeAmount <= 0) {
            error_log('Invalid fee amount: ' . $feeAmount);
            throw new Exception('Invalid fee amount');
        }
        
        $stripeKey = $_ENV['STRIPE_SECRET_KEY'] ?? '';
        
        if (empty($stripeKey)) {
            error_log('Stripe configuration missing');
            throw new Exception('Stripe configuration missing');
        }
        
        \Stripe\Stripe::setApiKey($stripeKey);
        
        // Create a product for the one-time payment
        $product = \Stripe\Product::create([
            'name' => 'Copilot License Savings',
            'description' => 'One-time payment for Copilot license savings of $' . number_format($savingsAmount, 2),
        ]);
        
        error_log('Created Stripe product: ' . $product->id);
        
        // Create a price with the calculated fee amount
        $price = \Stripe\Price::create([
            'product' => $product->id,
            'unit_amount' => round($feeAmount * 100), // Convert to cents
            'currency' => 'usd',
        ]);
        
        error_log('Created Stripe price: ' . $price->id);
        
        // Create a checkout session with the inline price
        $checkout_session = \Stripe\Checkout\Session::create([
            'payment_method_types' => ['card'],
            'line_items' => [[
                'price' => $price->id,
                'quantity' => 1,
            ]],
            'mode' => 'payment',
            'success_url' => $redirectUri . '?save_success=1&payment_id={CHECKOUT_SESSION_ID}',
            'cancel_url' => $redirectUri . '?save_canceled=1',
            'metadata' => [
                'github_org' => $org,
                'savings_amount' => $savingsAmount,
                'fee_amount' => $feeAmount,
            ],
        ]);

        error_log('Created Stripe checkout session: ' . $checkout_session->id);
        error_log('Redirecting to: ' . $checkout_session->url);

        header("Location: " . $checkout_session->url);
        exit();
    } catch (Exception $e) {
        error_log('Save Now payment error: ' . $e->getMessage());
        error_log('Stack trace: ' . $e->getTraceAsString());
        http_response_code(400);
        exit('Payment creation failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
    }
}

// Define userId for audit logs
$userId = $_SESSION['user_id'] ?? 'unknown';

// Get audit logs for the current user
$logs = [];
$stmt = $db->prepare("SELECT * FROM gh_api_audit_logs WHERE github_org = :org AND user_id = :user_id ORDER BY created_at DESC LIMIT 100");
$stmt->bindValue(':org', $org, SQLITE3_TEXT);
$stmt->bindValue(':user_id', $userId, SQLITE3_TEXT);
$result = $stmt->execute();

while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $logs[] = $row;
}

// Format the logs for display
$formattedLogs = [];
foreach ($logs as $log) {
    $formattedLogs[] = [
        'id' => $log['id'],
        'action_type' => 'Seat Disabling',
        'endpoint' => '/copilot/billing/selected_users',
        'request_method' => 'DELETE',
        'request_data' => json_encode(['request' => $log['request']], JSON_PRETTY_PRINT),
        'response_status' => empty($log['errors']) ? 200 : 400,
        'response_data' => json_encode([
            'seats_disabled' => $log['seats_disabled'],
            'total_inactive_seats' => $log['total_inactive_seats'],
            'savings_amount' => $log['savings_amount']
        ], JSON_PRETTY_PRINT),
        'error_message' => $log['errors'],
        'created_at' => date('Y-m-d H:i:s', strtotime($log['created_at']))
    ];
}

?>

<!DOCTYPE html>
<html>
<head>
    <title>Copilot License Monitoring</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://js.stripe.com/v3/"></script>
    <script src="js/save-now.js"></script>
    <script src="js/script.js"></script>
    <script defer src="https://cloud.umami.is/script.js" data-website-id="fbf39905-9461-4054-b1d2-ed35013c8dce"></script>
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
            background: linear-gradient(135deg, #d2f4e8 0%, #a8e6cf 100%);
            color: #1c1c1e;
            padding: 28px;
            border-radius: 16px;
            margin: 24px 0;
            box-shadow: 0 12px 24px rgba(0, 0, 0, 0.08);
            font-family: 'Inter', sans-serif;
            text-align: center;
        }

        .savings-card h2 {
            margin: 0 0 12px 0;
            font-size: 26px;
            font-weight: 600;
            color: #0c4a35;
        }

        .savings-amount {
            font-size: 48px;
            font-weight: 700;
            color: #087f5b;
            margin: 10px 0;
        }

        .savings-card p {
            margin: 0;
            font-size: 16px;
            color: #1f2937;
        }

        .action-buttons {
            display: flex;
            justify-content: center;
            gap: 12px;
            margin-top: 20px;
        }

        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-size: 16px;
        }

        .btn-primary {
            background: #2563eb; /* Deep Blue */
            color: white;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
        }

        .btn-primary:hover {
            background: #1d4ed8;
        }

        .btn-secondary {
            background: white;
            color: #2563eb;
            border: 2px solid #2563eb;
        }

        .btn-secondary:hover {
            background: #f0f4ff;
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
        
        .payment-status {
            background: #f6f8fa;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .payment-status.active {
            background: #e6f3ff;
            border-left: 4px solid #0366d6;
        }
        
        .payment-status.inactive {
            background: #fff8c5;
            border-left: 4px solid #f9c513;
        }
        
        .payment-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .payment-badge.active {
            background: #0366d6;
            color: white;
        }
        
        .payment-badge.inactive {
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
        
        /* User avatar styles */
        .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            object-fit: cover;
        }
        
        /* Team badge styles */
        .team-badge {
            display: inline-block;
            background-color: #f1f8ff;
            color: #0366d6;
            border: 1px solid #c8e1ff;
            border-radius: 12px;
            padding: 2px 8px;
            font-size: 12px;
            margin-right: 5px;
            margin-bottom: 5px;
        }
        
        /* Error summary styles */
        .error-summary {
            background: #fff8c5;
            border-left: 4px solid #f9c513;
            padding: 15px;
            margin: 20px 0;
            border-radius: 6px;
        }
        
        .error-summary h3 {
            color: #cb2431;
            margin-top: 0;
        }
        
        .error-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .error-table th, .error-table td {
            padding: 10px 15px;
            text-align: left;
            border-bottom: 1px solid #e1e4e8;
        }
        
        .error-table th {
            background-color: #f6f8fa;
            font-weight: 600;
            color: #24292e;
        }
        
        .error-table tr:hover {
            background-color: #f6f8fa;
        }
        
        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: #fefefe;
            margin: 10% auto;
            padding: 30px;
            border-radius: 8px;
            width: 80%;
            max-width: 500px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #24292e;
        }
        
        #email-form {
            margin-top: 20px;
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        #user-email {
            padding: 12px;
            border: 1px solid #e1e4e8;
            border-radius: 6px;
            font-size: 16px;
        }
        
        /* Loading indicator styles */
        .loading-indicator {
            margin-top: 15px;
            padding: 15px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 6px;
            text-align: center;
        }
        
        .spinner {
            display: inline-block;
            width: 30px;
            height: 30px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
            margin-bottom: 10px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* New audit logs styles */
        .audit-logs {
            margin-top: 2rem;
        }

        .audit-logs .card {
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .audit-logs .card-header {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .audit-logs .card-header h5 {
            margin: 0;
            color: #212529;
            font-weight: 600;
        }

        .audit-logs .table {
            width: 100%;
            margin: 0;
        }

        .audit-logs .table th {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #e9ecef;
        }

        .audit-logs .table td {
            padding: 1rem 1.5rem;
            vertical-align: middle;
            border-bottom: 1px solid #e9ecef;
            color: #495057;
        }

        .audit-logs .table tr:last-child td {
            border-bottom: none;
        }

        .audit-logs .table tr:hover {
            background-color: #f8f9fa;
        }

        .audit-logs .badge {
            padding: 0.5em 0.75em;
            font-weight: 500;
            border-radius: 4px;
        }

        .audit-logs .badge-success {
            background-color: #d4edda;
            color: #155724;
        }

        .audit-logs .badge-danger {
            background-color: #f8d7da;
            color: #721c24;
        }

        .audit-logs .btn-view {
            padding: 0.375rem 0.75rem;
            font-size: 0.875rem;
            border-radius: 4px;
            background-color: #e9ecef;
            color: #495057;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
        }

        .audit-logs .btn-view:hover {
            background-color: #dee2e6;
        }

        .audit-logs .log-details {
            background-color: #f8f9fa;
            border-radius: 4px;
            padding: 1rem;
            margin-top: 0.5rem;
        }

        .audit-logs .log-details pre {
            background-color: #fff;
            padding: 1rem;
            border-radius: 4px;
            border: 1px solid #e9ecef;
            margin: 0;
            font-size: 0.875rem;
            line-height: 1.5;
            overflow-x: auto;
        }

        .audit-logs .log-details h6 {
            color: #495057;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }

        .audit-logs .log-details .text-danger {
            color: #dc3545;
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
        <div style="max-width: 600px; margin: 40px auto; padding: 30px; background: #f9f9f9; border-radius: 12px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.1); font-family: sans-serif;">
            <h2 style="margin-bottom: 16px; color: #333;">Cut GitHub Copilot Costs with Confidence</h2>
            <p style="font-size: 16px; color: #555; margin-bottom: 24px;">
                See exactly who's using their Copilot seat and where you're overspending. Gain instant visibility into your team's activity and free up unused licenses in seconds.
            </p>
<p style="font-size: 14px; color: #d9534f; font-weight: bold; margin-bottom: 24px;">
    🔐 You must be an organization owner and authorize with <code>manage_billing:copilot</code> and <code>read:org</code> scopes to use this tool.
  </p>
        </div>
        <a href="https://github.com/login/oauth/authorize?client_id=<?= htmlspecialchars($clientId) ?>&redirect_uri=<?= urlencode($redirectUri) ?>&scope=read:org,manage_billing:copilot&state=<?= htmlspecialchars($_SESSION['oauth_state']) ?>">
            Login with GitHub
        </a>
    <?php else: ?>
        <h3>Organization: <?= htmlspecialchars($org) ?></h3>

        <?php if (!empty($inactiveSeats)): ?>
            <div class="savings-card">
                <h2><?= isset($paid) && $paid ? 'Monthly Savings' : 'Potential Monthly Savings' ?></h2>
                <div class="savings-amount">$<?= number_format($totalPotentialSavings, 2) ?></div>
                <p><?= isset($paid) && $paid ? 'You have a monthly savings of $' . number_format($totalPotentialSavings, 2) : 'You could save this amount by removing ' . count($inactiveSeats) . ' inactive seats' ?></p>
                <div class="action-buttons">
                    <?php if (isset($paid) && $paid): ?>
                        <button class="btn btn-primary" id="subscribe-cta-button">
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                <path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zm0 14.5a6.5 6.5 0 1 1 0-13 6.5 6.5 0 0 1 0 13z"/>
                                <path d="M8 4a.75.75 0 0 1 .75.75v3.5h3.5a.75.75 0 0 1 0 1.5h-3.5v3.5a.75.75 0 0 1-1.5 0v-3.5h-3.5a.75.75 0 0 1 0-1.5h3.5v-3.5A.75.75 0 0 1 8 4z"/>
                            </svg>
                            Get Monthly Savings Reports for $9.99
                        </button>
                    <?php else: ?>
                        <!-- JavaScript approach -->
                        <a href="#" class="btn btn-primary" id="save-now-button" 
                           data-savings-amount="<?= $totalPotentialSavings ?>"
                           data-csrf-token="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                <path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0z"/>
                            </svg>
                            Save Now
                        </a>
                        
                        <!-- Direct form submission approach -->
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <input type="hidden" name="save_now" value="1">
                            <input type="hidden" name="savings_amount" value="<?= 
                                $totalPotentialSavings > 500 ? 100 : 
                                ($totalPotentialSavings >= 100 ? $totalPotentialSavings * 0.2 : $totalPotentialSavings * 0.4) 
                            ?>">
                            <button type="submit" class="btn btn-primary" style="display: none;">
                                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                    <path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0z"/>
                                </svg>
                                Save Now (Direct)
                            </button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>

            <?php if (isset($paid) && $paid): ?>
                <?php if (isset($_SESSION['seat_disabling_errors']) && !empty($_SESSION['seat_disabling_errors'])): ?>
                <div class="error-summary">
                    <h3>Some seats could not be disabled</h3>
                    <p>The following seats could not be disabled due to API errors:</p>
                    <table class="error-table">
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Error</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($_SESSION['seat_disabling_errors'] as $error): ?>
                                <tr>
                                    <td><?= htmlspecialchars($error['username']) ?></td>
                                    <td><?= htmlspecialchars($error['error']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php 
                // Clear the errors from session after displaying
                unset($_SESSION['seat_disabling_errors']);
                endif; 
                ?>
            <?php endif; ?>

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

            <?php if (!empty($seats) && isset($seats['total_seats'])): ?>
                <div class="stats">
                    <strong>Total Seats:</strong> <?= (int)$seats['total_seats'] ?>
                </div>
            <?php endif; ?>
            <table class="seats-table">
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Last Active</th>
                        <th>Last Activity Editor</th>
                        <th>Plan Type</th>
                        <th>Assigning Team</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($seats['seats'] as $seat): ?>
                        <tr>
                            <td>
                                <div class="user-info">
                                    <img src="<?= htmlspecialchars($seat['assignee']['avatar_url'] ?? '') ?>" alt="<?= htmlspecialchars($seat['assignee']['login']) ?>" class="user-avatar">
                                    <a href="<?= htmlspecialchars($seat['assignee']['html_url'] ?? '#') ?>" target="_blank"><?= htmlspecialchars($seat['assignee']['login']) ?></a>
                                </div>
                            </td>
                            <td><?= htmlspecialchars($seat['last_activity_at'] ?? 'N/A') ?></td>
                            <td><?= htmlspecialchars($seat['last_activity_editor'] ?? 'N/A') ?></td>
                            <td><?= htmlspecialchars($seat['plan_type'] ?? 'N/A') ?></td>
                            <td><span class="team-badge"><?= htmlspecialchars($seat['assigning_team']['name'] ?? 'N/A') ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
        
        <!-- Audit Logs Section -->
        <div class="audit-logs">
            <div class="card">
                <div class="card-header">
                    <h5>Audit Logs</h5>
                    <span class="badge bg-primary"><?php echo count($formattedLogs); ?> entries</span>
                </div>
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Action</th>
                                <th>Endpoint</th>
                                <th>Method</th>
                                <th>Status</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($formattedLogs as $log): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($log['created_at']); ?></td>
                                <td><?php echo htmlspecialchars($log['action_type']); ?></td>
                                <td><?php echo htmlspecialchars($log['endpoint']); ?></td>
                                <td><span class="badge badge-info"><?php echo htmlspecialchars($log['request_method']); ?></span></td>
                                <td>
                                    <?php if ($log['response_status'] >= 200 && $log['response_status'] < 300): ?>
                                        <span class="badge badge-success"><?php echo $log['response_status']; ?></span>
                                    <?php else: ?>
                                        <span class="badge badge-danger"><?php echo $log['response_status']; ?></span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <button class="btn-view" data-log-id="<?php echo $log['id']; ?>">
                                        <i class="bi bi-eye"></i> View
                                    </button>
                                </td>
                            </tr>
                            <tr class="log-details-row" id="log-details-<?php echo $log['id']; ?>" style="display: none;">
                                <td colspan="6">
                                    <div class="log-details">
                                        <h6>Request Details</h6>
                                        <pre><code><?php echo htmlspecialchars($log['request_data']); ?></code></pre>
                                        
                                        <h6 class="mt-3">Response Details</h6>
                                        <pre><code><?php echo htmlspecialchars($log['response_data']); ?></code></pre>
                                        
                                        <?php if (!empty($log['error_message'])): ?>
                                        <h6 class="mt-3 text-danger">Error Message</h6>
                                        <pre class="text-danger"><code><?php echo htmlspecialchars($log['error_message']); ?></code></pre>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <?php if (isset($_SESSION['user_id'])): ?>
        <div class="logout">
            <a href="<?= htmlspecialchars($redirectUri) ?>?logout=1&csrf_token=<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">Log out</a>
        </div>
    <?php endif; ?>

    <div class="footer">
        <a href="privacy.php">Privacy Policy</a>
        <a href="https://github.com/LeeU1911/Copilot-Lic-Mon" target="_blank">GitHub</a>
    </div>

    <!-- payment Modal -->
    <div id="payment-modal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h2>Monthly Savings Reports Coming Soon!</h2>
            <p>We're launching a new feature that will automatically monitor your GitHub Copilot licenses and provide monthly savings reports for just $9.99/month.</p>
            <p>Leave your email below to be notified when this feature launches!</p>
            <form id="email-form">
                <input type="email" id="user-email" placeholder="Your email address" required>
                <button type="submit" class="btn btn-primary">Notify Me</button>
            </form>
            <div id="form-success" style="display: none; margin-top: 15px; color: #2ea44f;">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style="margin-right: 8px; vertical-align: middle;">
                    <path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0z"/>
                </svg>
                Thank you! We'll notify you when the feature launches.
            </div>
        </div>
    </div>

</body>
</html>
