<?php

namespace CodeIgniter\Shield\Authentication;

use CodeIgniter\HTTP\Exceptions\HTTPException;
use Exception;

class AuthenticationException extends Exception
{
    protected $code = 403;

    public static function forUnknownHandler(string $handler): self
    {
        return new self(lang('Auth.unknownHandler', [$handler]));
    }

    public static function forUnknownUserProvider(): self
    {
        return new self(lang('Auth.unknownUserProvider'));
    }

    public static function forInvalidUser(): self
    {
        return new self(lang('Auth.invalidUser'));
    }

    public static function forNoEntityProvided(): self
    {
        return new self(lang('Auth.noUserEntity'), 500);
    }

    /**
     * Fires when no minimumPasswordLength has been set
     * in the Auth config file.
     *
     * @return self
     */
    public static function forUnsetPasswordLength()
    {
        return new self(lang('Auth.unsetPasswordLength'), 500);
    }

    /**
     * When the cURL request (to Have I Been Pwned) in PwnedValidator
     * throws a HTTPException it is re-thrown as this one
     *
     * @return self
     */
    public static function forHIBPCurlFail(HTTPException $e)
    {
        return new self($e->getMessage(), $e->getCode(), $e);
    }
}
