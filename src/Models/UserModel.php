<?php

namespace CodeIgniter\Shield\Models;

use CodeIgniter\Model;
use CodeIgniter\Shield\Authentication\Traits\UserProvider as UserProviderTrait;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Interfaces\Authenticatable;
use CodeIgniter\Shield\Interfaces\UserProvider;
use Faker\Generator;
use InvalidArgumentException;

class UserModel extends Model implements UserProvider
{
    use UserProviderTrait;

    protected $table          = 'users';
    protected $primaryKey     = 'id';
    protected $returnType     = User::class;
    protected $useSoftDeletes = true;
    protected $allowedFields  = [
        'username',
        'status',
        'status_message',
        'active',
        'last_active',
        'deleted_at',
        'permissions',
    ];
    protected $useTimestamps = true;
    protected $afterFind     = ['fetchIdentities'];

    /**
     * Whether identity records should be included
     * when user records are fetched from the database.
     */
    protected bool $fetchIdentities = false;

    /**
     * Mark the next find* query to include identities
     *
     * @return $this
     */
    public function withIdentities()
    {
        $this->fetchIdentities = true;

        return $this;
    }

    /**
     * Populates identities for all records
     * returned from a find* method. Called
     * automatically when $this->fetchIdentities == true
     *
     * Model event callback called `afterFind`.
     */
    protected function fetchIdentities(array $data): array
    {
        if (! $this->fetchIdentities) {
            return $data;
        }

        $userIds = $data['singleton']
            ? array_column($data, 'id')
            : array_column($data['data'], 'id');

        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        // Get our identities for all users
        $identities = $identityModel->getIdentitiesByUserIds($userIds);

        if (empty($identities)) {
            return $data;
        }

        // Map our users by ID to make assigning simpler
        $mappedUsers = [];
        $users       = $data['singleton']
            ? $data
            : $data['data'];

        foreach ($users as $user) {
            $mappedUsers[$user->id] = $user;
        }
        unset($users);

        // Now assign the identities to the user
        foreach ($identities as $id) {
            $array                                 = $mappedUsers[$id->user_id]->identities;
            $array[]                               = $id;
            $mappedUsers[$id->user_id]->identities = $array;
        }

        $data['data'] = $mappedUsers;

        return $data;
    }

    /**
     * Adds a user to the default group.
     * Used during registration.
     */
    public function addToDefaultGroup(Authenticatable $user): void
    {
        $defaultGroup  = setting('AuthGroups.defaultGroup');
        $allowedGroups = array_keys(setting('AuthGroups.groups'));

        if (empty($defaultGroup) || ! in_array($defaultGroup, $allowedGroups, true)) {
            throw new InvalidArgumentException(lang('Auth.unknownGroup', [$defaultGroup ?? '--not found--']));
        }

        $user->addGroup($defaultGroup);
    }

    public function fake(Generator &$faker): array
    {
        return [
            'id'       => $faker->randomNumber(5, true),
            'username' => $faker->userName,
            'active'   => true,
        ];
    }
}
