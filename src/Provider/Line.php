<?php

namespace GNOffice\OAuth2\Client\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use GNOffice\OAuth2\Client\Provider\Exception\LineIdentityProviderException;
use GNOffice\OAuth2\Client\Provider\Exception\InvalidTokenException;

class Line extends AbstractProvider
{

    use BearerAuthorizationTrait;

    protected $openid_configuration;

    /**
     * @var string
     */
    protected $nonce;

    /**
     * Returns the base URL for authorizing a client.
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return 'https://access.line.me/oauth2/v2.1/authorize';
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return 'https://api.line.me/oauth2/v2.1/token';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return 'https://api.line.me/v2/profile';
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return ['profile', 'openid'];
    }

    protected function getScopeSeparator()
    {
        return ' ';
    }

    /**
     * Returns authorization parameters based on provided options.
     *
     * @param  array $options
     * @return array Authorization parameters
     */
    protected function getAuthorizationParameters(array $options)
    {
        // nonce
        if (empty($options['nonce'])) {
            $options['nonce'] = $this->getRandomState();
        }

        // Store the nonce as it may need to be accessed later on.
        $this->nonce = $options['nonce'];

        // 親クラスのパラメータを追加
        $options = parent::getAuthorizationParameters($options);

        return $options;
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw LineIdentityProviderException::clientException($response, $data);
        } elseif (isset($data['error'])) {
            throw LineIdentityProviderException::oauthException($response, $data);
        }
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return LineResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new LineResourceOwner($response);
    }

    /**
     * Returns the current value of the nonce parameter.
     *
     * This can be accessed by the redirect handler during authorization.
     *
     * @return string
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * IDトークンの検証を行う
     * @param string $jwt 取得した ID Token(JWT)
     * @param string $nonce トークン取得時に設定した nonce
     * @return void
     */
    public function verifyIdToken($jwt, $nonce)
    {
        $url = 'https://api.line.me/oauth2/v2.1/verify';

        $client = new Client();

        try {
            $response = $client->post($url, [
                'form_params' => [
                    'id_token' => $jwt,
                    'client_id' => $this->clientId,
                    'nonce' => $nonce
                ]
            ]);
        } catch (ClientException $e) {
            $contents = $e->getResponse()->getBody()->getContents();
            throw new InvalidTokenException($this->parseJson($contents)['error_description']);
        }

        $parsed_response = $this->parseResponse($response);
        return;
    }

    /**
     * アクセストークンの検証を行う
     * @param string $access_token 取得した Access Token
     * @return void
     */
    public function verifyAccessToken($access_token)
    {
        $url = 'https://api.line.me/oauth2/v2.1/verify';

        $client = new Client();

        try {
            $response = $client->get($url, [
                'query' => [
                    'access_token' => $access_token
                ]
            ]);
        } catch (ClientException $e) {
            $contents = $e->getResponse()->getBody()->getContents();
            throw new InvalidTokenException($this->parseJson($contents)['error_description']);
        }

        return;
    }

    /**
     * Get user email
     * @param string $jwt 取得した ID Token(JWT)
     * @param string $nonce トークン取得時に設定した nonce
     * @return string|null
     */
    public function getEmail($jwt, $nonce)
    {
        $url = 'https://api.line.me/oauth2/v2.1/verify';

        $client = new Client();

        try {
            $response = $client->post($url, [
                'form_params' => [
                    'id_token' => $jwt,
                    'client_id' => $this->clientId,
                    'nonce' => $nonce
                ]
            ]);
        } catch (ClientException $e) {
            $contents = $e->getResponse()->getBody()->getContents();
            throw new InvalidTokenException($this->parseJson($contents)['error_description']);
        }

        $parsed_response = $this->parseResponse($response);
        $email = $parsed_response['email'];
        return $email;
    }

}