<?php


namespace Grocy\Auth;


use Grocy\Services\SessionService;
use Psr\Http\Message\ServerRequestInterface as Request;

class SessionAuthProvider extends AuthProvider
{
    public function __construct($sessionCookieName)
    {
        $this->SessionCookieName = $sessionCookieName;
    }

    protected $SessionCookieName;

    /**
     * @inheritDoc
     */
    function authenticate(Request $request)
    {
        $sessionService = SessionService::getInstance();
        if (!isset($_COOKIE[$this->SessionCookieName]) || !$sessionService->IsValidSession($_COOKIE[$this->SessionCookieName])) {
            return null;
        } else {
            return $sessionService->GetUserBySessionKey($_COOKIE[$this->SessionCookieName]);
        }
    }
}