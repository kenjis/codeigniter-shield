<?php

namespace CodeIgniter\Shield\Entities;

use CodeIgniter\Entity\Entity;
use Sparks\Shield\Authentication\Passwords;

/**
 * Class UserIdentity
 *
 * Represents a single set of user identity credentials.
 * For the base Shield system, this would be one of the following:
 *  - password
 *  - reset hash
 *  - access token
 *
 * This can also be used to store credentials for social logins,
 * OAUTH or JWT tokens, etc. A user can have multiple of each,
 * though a handler may want to enforce only one exists for that
 * user, like a password.
 */
class UserIdentity extends Entity
{
    protected $casts = [
        'force_reset' => 'boolean',
    ];
    protected $dates = [
        'expires',
        'last_used_at',
    ];

    /**
     * Uses password-strength hashing to hash
     * a given value for the 'secret'.
     *
     * @return \CodeIgniter\Shield\Entities\UserIdentity
     */
    public function hashSecret(string $value)
    {
        /** @var Passwords $passwords */
        $passwords = service('passwords');

        $this->attributes['secret'] = $passwords->hash($value);

        return $this;
    }
}
