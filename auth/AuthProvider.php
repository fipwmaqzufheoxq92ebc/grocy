<?php


namespace Grocy\Auth;


use Psr\Http\Message\ServerRequestInterface as Request;

abstract class AuthProvider
{
    /**
     * @param Request $request
     * @return mixed a user row
     */
    abstract function authenticate(Request $request);
}