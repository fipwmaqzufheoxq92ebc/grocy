<?php


namespace Grocy\Middleware;


use Grocy\Auth\ApiKeyAuthProvider;
use Grocy\Auth\ProxyAuthProvider;
use Grocy\Auth\SessionAuthProvider;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Routing\RouteContext;

class AuthMiddleware extends BaseMiddleware
{
    public function __construct(\DI\Container $container, ResponseFactoryInterface $responseFactory)
    {
        parent::__construct($container);
        $this->ResponseFactory = $responseFactory;
    }

    protected $ResponseFactory;

    public function __invoke(Request $request, RequestHandler $handler): Response
    {
        $routeContext = RouteContext::fromRequest($request);
        $route = $routeContext->getRoute();
        $routeName = $route->getName();
        if ($routeName === 'root') {
            return $handler->handle($request);
        }
        if ($routeName === 'login') {
            define('GROCY_AUTHENTICATED', false);
            return $handler->handle($request);
        }
        if (GROCY_MODE === 'dev' || GROCY_MODE === 'demo' || GROCY_MODE === 'prerelease' || GROCY_IS_EMBEDDED_INSTALL || GROCY_DISABLE_AUTH) {
            define('GROCY_AUTHENTICATED', true);
            return $handler->handle($request);
        } else {
            $user = $this->authenticate($request);
            if ($user === null) {
                define('GROCY_AUTHENTICATED', false);
                $response = $this->ResponseFactory->createResponse();
                return $response->withHeader('Location', $this->AppContainer->get('UrlManager')->ConstructUrl('/login'));
            } else {
                define('GROCY_AUTHENTICATED', true);
                define('GROCY_USER_ID', $user->id);
                define('GROCY_USER_USERNAME', $user->username);

                return $response = $handler->handle($request);
            }
        }
    }

    /**
     * @param Request $request
     * @return mixed|null the user row or null if the request is not authenticated
     * @throws \Exception Throws an \Exception if config is invalid.
     */
    protected function authenticate(Request $request)
    {
        $providers = GROCY_AUTH_PROVIDER;
        if (!is_array($providers)) {
            $providers = array(GROCY_AUTH_PROVIDER);
        }
        foreach ($providers as $key => $provider) {
            switch ($provider) {
                case 'PROXY':
                    $auth = new ProxyAuthProvider();
                    $user = $auth->authenticate($request);
                    break;
                case 'API_KEY':
                    $auth = new ApiKeyAuthProvider($this->AppContainer->get('ApiKeyHeaderName'));
                    $user = $auth->authenticate($request);
                    break;
                case 'SESSION':
                    $auth = new SessionAuthProvider($this->AppContainer->get('LoginControllerInstance')->GetSessionCookieName());
                    $user = $auth->authenticate($request);
                    break;
                default:
                    throw new \Exception('Invalid auth provider');
            }
            if ($user !== null)
                return $user;
        }
        return null;
    }


}