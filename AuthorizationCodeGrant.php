<?php
/**
 * Doc. https://oauth2-client.thephpleague.com/usage/
 * 
 */
session_start();
require_once __DIR__ . "/vendor/autoload.php";
require_once __DIR__ . "/_config.php";

if (empty($_GET['jeedom_id']))  {  die('missing id'); }
$jeedom_id = (filter_var($_GET['jeedom_id'], FILTER_SANITIZE_STRING));


$provider = new \League\OAuth2\Client\Provider\GenericProvider([
    'clientId'              => CLIENT_ID,    // The client ID assigned to you by the provider
    'clientSecret'          => CLIENT_SECRET,    // The client password assigned to you by the provider
    'redirectUri'           => REDIRECT_URI_BASE . '/AuthorizationCodeGrant.php?jeedom_id=' .  $jeedom_id,
    'urlAuthorize'          => 'https://api.netatmo.com/oauth2/authorize',
    'urlAccessToken' => 'https://api.netatmo.com/oauth2/token',
    'urlResourceOwnerDetails' => 'https://service.example.com/resource'
]);

// If we don't have an authorization code then get one
if (!isset($_GET['code'])) {

    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl([
        'scope' => ['read_station']
    ]);

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || empty($_SESSION['oauth2state']) || $_GET['state'] !== $_SESSION['oauth2state']) {

    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }

    exit('Invalid state');

} else {

    try {
    
        // Try to get an access token using the authorization code grant.
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        // We have an access token, which we may use in authenticated
        // requests against the service provider's API.
        
        // echo 'Access Token: ' . $accessToken->getToken() . "<br>";
        // echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
        // echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
        // echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";
        // echo $jeedom_id;
        
        
        
        // Connect MySQL
        $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($mysqli->connect_errno) { die("Connect failed: " . $mysqli->connect_error); }
        

        // Delete previous tokens
        $query = sprintf("DELETE FROM `netatmoPublicData` WHERE `jeedom_id` = '%s';", 
                    $mysqli->real_escape_string($jeedom_id),
                    );
        if (!$mysqli->query($query)) { die("Error message: " . $mysqli->error); }
        
        // Save new ones
        $query = sprintf("INSERT INTO `netatmoPublicData` (`jeedom_id`, `npd_access_token`, `npd_refresh_token`, `npd_expires_at`, `created` )
        VALUES ('%s', '%s', '%s', '%s', NOW());", 
            $mysqli->real_escape_string($jeedom_id),
            $mysqli->real_escape_string($accessToken->getToken()),
            $mysqli->real_escape_string($accessToken->getRefreshToken()),
            $mysqli->real_escape_string($accessToken->getExpires())
            );
        // echo $query;
          
        if (!$mysqli->query($query)) { die("Error message: " . $mysqli->error); }

        echo "✅";


    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

        // Failed to get the access token or user details.
        exit($e->getMessage());

    }

}
