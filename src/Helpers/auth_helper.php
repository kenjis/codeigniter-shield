<?php

use CodeIgniter\Shield\Auth;

if (! function_exists('auth')) {
    /**
     * Provides convenient access to the main Auth class
     * for CodeIgniter Shield.
     */
    function auth(?string $authenticator = null): Auth
    {
        /** @var Auth $auth */
        $auth = service('auth');

        return $auth->setHandler($authenticator);
    }
}

if (! function_exists('user_id')) {
    /**
     * Returns the ID for the current logged in user.
     * Note: For \CodeIgniter\Shield\Entities\User this will always return an int.
     *
     * @return int|string|null
     */
    function user_id()
    {
        /** @var Auth $auth */
        $auth = service('auth');

        return $auth->id();
    }
}
