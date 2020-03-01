<?php

namespace GNOffice\OAuth2\Client\Test\Provider;

use GNOffice\OAuth2\Client\Provider\Line;
use Mockery as m;
use ReflectionClass;
use PHPUnit\Framework\TestCase;

class LineTest extends TestCase
{
    protected $provider;

    protected static function getMethod($name)
    {
        $class = new ReflectionClass('GNOffice\OAuth2\Client\Provider\Line');
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

    protected function setUp(): void
    {
        $this->provider = new Line([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'mock_redirect_uri',
        ]);
    }

    public function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('nonce', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('client_id', $query);
        $this->assertNotNull($this->provider->getState());
        $this->assertNotNull($this->provider->getNonce());
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];

        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);

        $this->assertEquals('/oauth2/v2.1/token', $uri['path']);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('/oauth2/v2.1/authorize', $uri['path']);
    }

    public function testGetResourceOwnerDetails()
    {
        $id = uniqid();
        $name = uniqid();
        $picture = uniqid();
        $status_message = uniqid();

        $token = m::mock('\League\OAuth2\Client\Token\AccessToken');
        $token->shouldReceive('getToken')->andReturn('mock_access_token');
        $token->shouldReceive('getValues')->andReturn(
            [
                'access_token' => 'mock_access_token',
                'token_type' => 'Bearer',
                'refresh_token' => 'mock_refresh_token',
                'expires_in' => 3600,
                'id_token' => 'mock_id_token'
            ]
        );

        $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getBody')->andReturn('{"userId":"' . $id . '","displayName":"' . $name . '","pictureUrl":"' . $picture . '","statusMessage":"' . $status_message . '"}');
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $userResponse->shouldReceive('getStatusCode')->andReturn(200);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn($userResponse);
        $this->provider->setHttpClient($client);

        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals($id, $user->getId());
        $this->assertEquals($id, $user->toArray()['userId']);
        $this->assertEquals($name, $user->getName());
        $this->assertEquals($name, $user->toArray()['displayName']);
        $this->assertEquals($picture, $user->getPicture());
        $this->assertEquals($picture, $user->toArray()['pictureUrl']);
    }
}
