<?php


namespace Grocy\Auth;


use Grocy\Services\ApiKeyService;
use Grocy\Services\SessionService;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Routing\RouteContext;

class ApiKeyAuthProvider extends AuthProvider
{
    public function __construct(string $apiKeyHeaderName)
    {
        $this->ApiKeyHeaderName = $apiKeyHeaderName;
    }

    protected $ApiKeyHeaderName;

    /**
     * @inheritDoc
     */
    function authenticate(Request $request)
    {
        $routeContext = RouteContext::fromRequest($request);
        $route = $routeContext->getRoute();
        $routeName = $route->getName();

        $validApiKey = true;
        $usedApiKey = null;


        $apiKeyService = new ApiKeyService();

        // First check of the API key in the configured header
        if (!$request->hasHeader($this->ApiKeyHeaderName) || !$apiKeyService->IsValidApiKey($request->getHeaderLine($this->ApiKeyHeaderName))) {
            $validApiKey = false;
        } else {
            $usedApiKey = $request->getHeaderLine($this->ApiKeyHeaderName);
        }

        // Not recommended, but it's also possible to provide the API key via a query parameter (same name as the configured header)
        if (!$validApiKey && !empty($request->getQueryParam($this->ApiKeyHeaderName)) && $apiKeyService->IsValidApiKey($request->getQueryParam($this->ApiKeyHeaderName))) {
            $validApiKey = true;
            $usedApiKey = $request->getQueryParam($this->ApiKeyHeaderName);
        }

        // Handling of special purpose API keys
        if (!$validApiKey) {
            if ($routeName === 'calendar-ical') {
                if ($request->getQueryParam('secret') !== null && $apiKeyService->IsValidApiKey($request->getQueryParam('secret'), ApiKeyService::API_KEY_TYPE_SPECIAL_PURPOSE_CALENDAR_ICAL)) {
                    $validApiKey = true;
                }
            }
        }

        if ($validApiKey) {
            return $apiKeyService->GetUserByApiKey($usedApiKey);

        } else {
            return null;
        }
    }
}