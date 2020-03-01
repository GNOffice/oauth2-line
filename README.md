# LINE Provider for OAuth 2.0 Client
This package provides LINE OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## Usage

```PHP
<?php
use GNOffice\OAuth2\Client\Provider\Line;

session_start();

$provider = new Line([
    'clientId' => '{line-channel-id}',
    'clientSecret' => '{line-channel-secret}',
    'redirectUri' => 'https://example.com/callback-url',
]);

// Get authorization code
if (!isset($_GET['code'])) {

    // Get authorization URL
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get state and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Get nonce and store it to the session.
    $_SESSION['oauth2nonce'] = $provider->getNonce();

    // Get code_verifier and store it to the session.
    $_SESSION['oauth2code_verifier'] = $provider->getCodeVerifier();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;

// Check for errors
} elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {

    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }

    exit('Invalid state');

} else {
    // Get access token
    try {
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code'],
            'nonce' => $_SESSION['oauth2nonce']
        ]);

        try {
            $nonce = $_SESSION['oauth2nonce'];

            $token_values = $accessToken->getValues();
            $id_token = $token_values['id_token'];
            $access_token = $accessToken->getToken();

            // Verify ID Token
            $verify_id_token = $provider->verifyIdToken($id_token, $nonce);

            // Verify Access Token
            $verify_token = $provider->verifyAccessToken($access_token);

            // Get resource owner
            $user = $provider->getResourceOwner($accessToken);

            $email = $provider->getEmail($id_token, $nonce);

            // Use these details to create a new profile
            printf('Hello %s!', $user->getName());
        } catch (GNOffice\OAuth2\Client\Provider\Exception\InvalidTokenException $e) {
            exit($e->getMessage());
        }

    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

        // Failed to get the access token or user details.
        exit($e->getMessage());

    }

    // Use this to interact with an API on the users behalf
    echo $accessToken->getToken();

}
```

## Testing
```
$ ./vendor/bin/phpunit
```

## License
The MIT License (MIT). Please see [License File](https://github.com/GNOffice/oauth2-line/blob/master/LICENSE) for more information.