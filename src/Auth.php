<?php

namespace CodeIgniter\Shield;

use CodeIgniter\Router\RouteCollection;
use CodeIgniter\Shield\Authentication\Authentication;
use CodeIgniter\Shield\Authentication\AuthenticationException;
use CodeIgniter\Shield\Authentication\AuthenticatorInterface;
use CodeIgniter\Shield\Interfaces\Authenticatable;
use CodeIgniter\Shield\Interfaces\UserProvider;

/**
 * @method Result               attempt(array $credentials)
 * @method Result               check(array $credentials)
 * @method Authenticatable|null getUser()
 * @method bool                 loggedIn()
 * @method bool                 login(Authenticatable $user)
 * @method bool                 loginById(int $userId)
 * @method bool                 logout()
 * @method void                 recordActive()
 */
class Auth
{
    protected Authentication $authenticate;

    /**
     * The handler to use for this request.
     */
    protected ?string $handler = null;

    protected ?Authenticatable $user      = null;
    protected ?UserProvider $userProvider = null;

    public function __construct(Authentication $authenticate)
    {
        $this->authenticate = $authenticate->setProvider($this->getProvider());
    }

    /**
     * Sets the handler that should be used for this request.
     *
     * @return $this
     */
    public function setHandler(?string $handler = null)
    {
        if (! empty($handler)) {
            $this->handler = $handler;
        }

        return $this;
    }

    /**
     * Returns the handler name.
     */
    public function getHandler(): string
    {
        assert($this->handler !== null, 'You must set $this->handler.');

        return $this->handler;
    }

    /**
     * Returns the current authentication class.
     */
    public function getAuthenticator(): AuthenticatorInterface
    {
        return $this->authenticate->factory($this->handler);
    }

    /**
     * Returns the current user, if logged in.
     */
    public function user(): ?Authenticatable
    {
        return $this->getAuthenticator()->loggedIn()
            ? $this->getAuthenticator()->getUser()
            : null;
    }

    /**
     * Returns the current user's id, if logged in.
     *
     * @return int|string|null
     */
    public function id()
    {
        return ($user = $this->user()) ? $user->getAuthId() : null;
    }

    public function authenticate(array $credentials): Result
    {
        $response = $this->authenticate->factory($this->handler)
            ->attempt($credentials);

        if ($response->isOk()) {
            $this->user = $response->extraInfo();
        }

        return $response;
    }

    /**
     * Will set the routes in your application to use
     * the Shield auth routes.
     *
     * Usage (in Config/Routes.php):
     *      - auth()->routes($routes);
     *      - auth()->routes($routes, ['except' => ['login', 'register']])
     */
    public function routes(RouteCollection &$routes, array $config = []): void
    {
        $authRoutes = config('AuthRoutes')->routes;

        $routes->group(
            '/',
            ['namespace' => 'CodeIgniter\Shield\Controllers'],
            static function (RouteCollection $routes) use ($authRoutes, $config) {
                foreach ($authRoutes as $name => $row) {
                    if (
                        ! isset($config['except'])
                        || (isset($config['except']) && ! array_key_exists($name, $config['except']))
                    ) {
                        foreach ($row as $params) {
                            $options = isset($params[3])
                            ? ['as' => $params[3]]
                            : null;
                            $routes->{$params[0]}($params[1], $params[2], $options);
                        }
                    }
                }
            }
        );
    }

    /**
     * Returns the Model that is responsible for getting users.
     *
     * @throws AuthenticationException
     */
    public function getProvider(): UserProvider
    {
        if ($this->userProvider !== null) {
            return $this->userProvider;
        }

        $config = config('Auth');

        if (! property_exists($config, 'userProvider')) {
            throw AuthenticationException::forUnknownUserProvider();
        }

        $className          = $config->userProvider;
        $this->userProvider = new $className();

        return $this->userProvider;
    }

    /**
     * Provide magic function-access to handlers to save use
     * from repeating code here, and to allow them have their
     * own, additional, features on top of the required ones,
     * like "remember-me" functionality.
     *
     * @param string[] $args
     *
     * @throws AuthenticationException
     */
    public function __call(string $method, array $args)
    {
        $authenticator = $this->authenticate->factory($this->handler);

        if (method_exists($authenticator, $method)) {
            return $authenticator->{$method}(...$args);
        }
    }
}
