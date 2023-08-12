<?php
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

require_once __DIR__ . "/_config.php";

if (empty($_GET['jeedom_id']))  {  die('missing id'); }
$jeedom_id = (filter_var($_GET['jeedom_id'], FILTER_SANITIZE_STRING));


// Connect MySQL
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_errno) { die("Connect failed: " . $mysqli->connect_error); }

// Get data stored
$query = sprintf("SELECT `npd_access_token`, `npd_refresh_token`, `npd_expires_at`, `refresh_count`  FROM `netatmoPublicData` WHERE `jeedom_id` = '%s' ORDER BY `netatmoPublicData`.`npd_expires_at` DESC LIMIT 1; ", $mysqli->real_escape_string($jeedom_id));
if (!$mysqli->query($query)) { die("Error message: " . $mysqli->error); }
else { $result = $mysqli->query($query); }
$tokens = $result->fetch_assoc();
$mysqli->close();




if (isset($_GET['refresh']) and !empty($tokens['npd_refresh_token'])) {
    
    require_once __DIR__ . "/vendor/autoload.php";
    
    $provider = new \League\OAuth2\Client\Provider\GenericProvider([
        'clientId'                => CLIENT_ID,    // The client ID assigned to you by the provider
        'clientSecret'            => CLIENT_SECRET,    // The client password assigned to you by the provider
        'redirectUri'             => REDIRECT_URI_BASE . '/AuthorizationCodeGrant.php?jeedom_id=' .  $jeedom_id,
        'urlAuthorize' => 'https://api.netatmo.com/oauth2/authorize',
        'urlAccessToken' => 'https://api.netatmo.com/oauth2/token',
        'urlResourceOwnerDetails' => 'https://service.example.com/resource'
    ]);
    

    $accessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $tokens['npd_refresh_token'],
    ]);
    
    // save it to MySQL
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
    if ($mysqli->connect_errno) { die("Connect failed: " . $mysqli->connect_error); }

    $query = sprintf("UPDATE `netatmoPublicData` 
                    SET `npd_access_token` = '%s', `npd_refresh_token` = '%s', `npd_expires_at` = '%s', `refresh_count` = '%s' 
                    WHERE `jeedom_id` = '%s';",
        $mysqli->real_escape_string($accessToken->getToken()),
        $mysqli->real_escape_string($accessToken->getRefreshToken()),
        $mysqli->real_escape_string($accessToken->getExpires()),
        $mysqli->real_escape_string($tokens['refresh_count'] + 1),
        $mysqli->real_escape_string($jeedom_id),
    );
    

    if (!$mysqli->query($query)) { die("Error message: " . $mysqli->error); }

    // loop back (without 'refresh') 
    header("HTTP/1.1 301 Moved Permanently");
    header('Location: ' . REDIRECT_URI_BASE . '/getTokens.php?jeedom_id=' .  $jeedom_id);
    exit;
}



// Return Data
$data =  array();
$data['state'] = "error"; // by default

if (!empty($tokens)) {
    $data['state'] = "ok";
    $data['npd_access_token'] = $tokens['npd_access_token'];
    $data['npd_refresh_token'] = $tokens['npd_refresh_token'];
    $data['npd_expires_at'] = $tokens['npd_expires_at'];
}


echo json_encode($data);
