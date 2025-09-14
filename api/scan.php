<?php
header("Content-Type: application/json; charset=utf-8");

// Read input JSON
$raw = file_get_contents("php://input");
$input = json_decode($raw, true);
if (!is_array($input) || empty($input['url'])) {
    http_response_code(400);
    echo json_encode(['status'=>'error','error' => 'Invalid input. Send JSON with {"url":"..."}']);
    exit;
}

$url = trim($input['url']);
if (!preg_match('#^https?://#i', $url)) {
    $url = 'http://' . $url;
}

// Flask ML API endpoint (ensure app.py is running)
$ml_api = "http://127.0.0.1:5000/scan";

$options = [
    'http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/json\r\n",
        'content' => json_encode(['url' => $url]),
        'timeout' => 8
    ]
];
$context = stream_context_create($options);

// call ML API
$ml_response = @file_get_contents($ml_api, false, $context);
if ($ml_response === false) {
    // include helpful debug (avoid leaking sensitive info in production)
    $err = error_get_last();
    $msg = isset($err['message']) ? $err['message'] : 'Cannot reach ML API';
    echo json_encode(['status'=>'error','error' => $msg]);
    exit;
}

// decode ML JSON (guard)
$ml_result = json_decode($ml_response, true);
if (!is_array($ml_result)) {
    echo json_encode(['status'=>'error','error' => 'ML API returned invalid JSON']);
    exit;
}

// Prepare response for frontend
$response = [
    'status' => 'ok',
    'url' => $url,
    'score' => isset($ml_result['score']) ? $ml_result['score'] : 0,
    'verdict' => isset($ml_result['verdict']) ? $ml_result['verdict'] : 'Unknown',
    'features' => isset($ml_result['features']) ? $ml_result['features'] : new stdClass(),
    'reasons' => isset($ml_result['reasons']) ? $ml_result['reasons'] : []
];

echo json_encode($response, JSON_UNESCAPED_UNICODE);
