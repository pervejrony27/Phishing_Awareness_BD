<?php
// api/scan.php
header("Content-Type: application/json; charset=utf-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Accept");

// handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Only POST allowed']);
    exit;
}

// read JSON
$raw = file_get_contents("php://input");
$input = json_decode($raw, true);
if (!is_array($input) || empty($input['url'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid input. Send JSON with {"url":"..."}']);
    exit;
}

$url = trim($input['url']);

// normalize (add scheme if missing)
if (!preg_match('#^https?://#i', $url)) {
    $url = 'http://' . $url;
}

// validate
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    echo json_encode([
        'status' => 'error',
        'verdict' => 'Invalid URL',
        'score' => 0,
        'reasons' => [
            ['en' => 'The provided text is not a valid URL.', 'bn' => 'দেওয়া টেক্সটটি একটি বৈধ URL নয়।']
        ]
    ]);
    exit;
}

// parse
$parts = parse_url($url);
$scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : '';
$host = isset($parts['host']) ? strtolower($parts['host']) : '';
$path = isset($parts['path']) ? $parts['path'] : '';
$query = isset($parts['query']) ? $parts['query'] : '';

$reasons = [];
$score = 0;

/* RULES WITH TEACHING MESSAGES (EN + BN) */

/* 1) HTTPS check */
if ($scheme !== 'https') {
    $score += 20;
    $reasons[] = [
        'en' => 'The URL does not use HTTPS (no SSL/TLS). Secure sites normally use HTTPS to protect your data.',
        'bn' => 'URL-টি HTTPS ব্যবহার করছে না (SSL/TLS নেই)। নিরাপদ সাইট সাধারণত আপনার ডেটা সুরক্ষিত রাখতে HTTPS ব্যবহার করে।'
    ];
} else {
    // positive message (optional)
    $reasons[] = [
        'en' => 'The site uses HTTPS — this is better than HTTP, but HTTPS alone does not guarantee safety.',
        'bn' => 'সাইটটি HTTPS ব্যবহার করে — এটি HTTP থেকে ভালো, কিন্তু কেবল HTTPS থাকা নিরাপদ হওয়ার নিশ্চয়তা দেয় না।'
    ];
}

/* 2) Long host or many subdomains/hyphens */
if (strlen($host) > 30) {
    $score += 8;
    $reasons[] = [
        'en' => 'The domain name is unusually long — attackers sometimes use long or complex domains to mimic real sites.',
        'bn' => 'ডোমেইন নামটি অস্বাভাবিকভাবে দীর্ঘ — হামলাকারীরা কখনও দীর্ঘ বা জটিল ডোমেইন ব্যবহার করে বাস্তব সাইটের মতো দেখানোর চেষ্টা করে।'
    ];
}
if (substr_count($host, '-') > 2) {
    $score += 5;
    $reasons[] = [
        'en' => 'The domain contains many hyphens — suspicious domains often use extra hyphens to imitate other names.',
        'bn' => 'ডোমেইনে অনেক হাইফেন রয়েছে — সন্দেহজনক ডোমেইনগুলো প্রায়ই নাম নকল করতে অতিরিক্ত হাইফেন ব্যবহার করে।'
    ];
}

/* 3) Suspicious keywords in host/path/query (banking, verify, login, otp, bkash, nagad, prize, free) */
$suspicious_keywords = ['login','verify','secure','bank','account','otp','confirm','update','payment','bkash','nagad','reward','prize','free','urgent'];
foreach ($suspicious_keywords as $kw) {
    if (stripos($host . $path . $query, $kw) !== false) {
        $score += 8;
        $reasons[] = [
            'en' => "The URL contains the keyword \"$kw\" — phishing links often use urgent-sounding words (login, verify, OTP, prize) to trick users.",
            'bn' => "URL-টিতে \"$kw\" শব্দটি আছে — ফিশিং লিংকগুলো প্রায়ই ব্যবহারকারীদের বিভ্রান্ত করতে দ্রুত বা জরুরী শব্দ (login, verify, OTP, prize) ব্যবহার করে।"
        ];
    }
}

/* 4) Raw IP address used */
if (filter_var($host, FILTER_VALIDATE_IP)) {
    $score += 15;
    $reasons[] = [
        'en' => 'The URL uses a raw IP address instead of a domain. Legitimate services rarely link directly to numeric IPs.',
        'bn' => 'URL-এ ডোমেইনের পরিবর্তে IP ঠিকানা ব্যবহার করা হয়েছে। সাধারণত বৈধ সেবা সরাসরি সংখ্যাজনিত IP ব্যবহার করে লিঙ্ক দেয় না।'
    ];
}

/* 5) Domain resolution & private IP check (SSRF defense) */
$ips = @gethostbynamel($host);
if ($ips === false || count($ips) === 0) {
    $score += 10;
    $reasons[] = [
        'en' => 'The hostname could not be resolved to an IP address — this may indicate a newly created, short-lived, or invalid domain.',
        'bn' => 'হোস্টনামটি কোনো IP-তে রেজলভ হচ্ছে না — এটি হতে পারে নতুন তৈরি, অল্পকালীন বা অবৈধ ডোমেইন।'
    ];
} else {
    foreach ($ips as $ip) {
        if (is_private_ip($ip)) {
            $score += 30;
            $reasons[] = [
                'en' => "The hostname resolves to a private/local IP ($ip) — this may indicate an attempt to reach internal resources or an SSRF risk.",
                'bn' => "হোস্টনামটি প্রাইভেট/লোকাল IP ( $ip )-এ রেজলভ করছে — এটি অভ্যন্তরীণ রিসোর্সে পৌঁছানোর চেষ্টা বা SSRF ঝুঁকিকে নির্দেশ করতে পারে।"
            ];
        }
    }
}

/* 6) Very long query strings (obfuscation) */
if (strlen($query) > 200) {
    $score += 7;
    $reasons[] = [
        'en' => 'The URL has a very long query string — attackers sometimes hide malicious payloads or trackers in long queries.',
        'bn' => 'URL-টিতে খুব লম্বা query string আছে — হামলাকারীরা লম্বা query-তে ক্ষতিকর তথ্য বা ট্র্যাকার লুকাতে পারে।'
    ];
}

/* 7) Rare/cheap TLDs used (like .tk, .ml, .ga) */
$hostParts = explode('.', $host);
$tld = array_pop($hostParts);
$rare_tlds = ['pw','tk','ml','ga','cf','gq'];
if (in_array($tld, $rare_tlds)) {
    $score += 6;
    $reasons[] = [
        'en' => "The top-level domain .$tld is frequently used for disposable or abusive domains.",
        'bn' => ".$tld TLD টি প্রায়ই অস্থায়ী বা দুর্ব্যবহৃত ডোমেইনের জন্য ব্যবহৃত হয়।"
    ];
}

/* 8) '@' in URL (confusing URL) */
if (strpos($url, '@') !== false) {
    $score += 7;
    $reasons[] = [
        'en' => "The URL contains '@'. Some phishing links use '@' to disguise the real destination.",
        'bn' => "URL-টিতে '@' আছে। কিছু ফিশিং লিংক আসল গন্তব্য গোপন করতে '@' ব্যবহার করে।"
    ];
}

/* If no strong reasons, add positive teaching notes */
if ($score < 20 && empty($reasons)) {
    $reasons[] = [
        'en' => 'No obvious suspicious patterns found. However, always check sender, short links, and request for OTP/passwords before trusting.',
        'bn' => 'প্রাথমিকভাবে কোনো সন্দেহজনক প্যাটার্ন পাওয়া যায়নি। তবুও, প্রেরক যাচাই করুন, সংক্ষিপ্ত লিঙ্ক সতর্কতার সঙ্গে দেখুন এবং OTP/পাসওয়ার্ড চাইলে সতর্ক থাকুন।'
    ];
}

/* final verdict */
$verdict = 'Likely Safe';
if ($score >= 60) $verdict = 'Likely Phishing';
elseif ($score >= 20) $verdict = 'Suspicious';

/* Optionally log the scan to DB — disabled by default.
try {
    $dbHost = '127.0.0.1'; $dbName = 'phishing_db'; $dbUser = 'root'; $dbPass = '';
    $pdo = new PDO("mysql:host=$dbHost;dbname=$dbName;charset=utf8mb4",$dbUser,$dbPass, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $stmt = $pdo->prepare("INSERT INTO scan_logs (url, host, score, verdict, reasons, ip_list, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
    $stmt->execute([$url, $host, $score, $verdict, json_encode($reasons, JSON_UNESCAPED_UNICODE), json_encode($ips)]);
} catch (Exception $e) {
    // ignore if DB not configured
}
*/

echo json_encode([
    'status' => 'ok',
    'url' => $url,
    'host' => $host,
    'score' => $score,
    'verdict' => $verdict,
    'reasons' => $reasons,
    'ips' => $ips
]);

/* ----------------------
   Helper: check private IP ranges
   ---------------------- */
function is_private_ip($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    // IPv4 check
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $long = ip2long($ip);
        $ranges = [
            ['10.0.0.0','10.255.255.255'],
            ['172.16.0.0','172.31.255.255'],
            ['192.168.0.0','192.168.255.255'],
            ['127.0.0.0','127.255.255.255'],
            ['169.254.0.0','169.254.255.255'],
        ];
        foreach ($ranges as $r) {
            if ($long >= ip2long($r[0]) && $long <= ip2long($r[1])) return true;
        }
    }
    // IPv6 or other checks omitted for brevity
    return false;
}
