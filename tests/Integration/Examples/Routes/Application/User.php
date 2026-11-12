<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Application;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The example application's user, as its authentication hands it to a route;
 * never stored, a test authenticates as one with `actingAs()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class User implements Authenticatable
{
    /** @var string The identity type the package records for a user. */
    public const string TYPE = 'App\Models\User';

    /**
     * A user of the tenant, on the session given.
     *
     * @param  string  $id
     * @param  string  $tenantId
     * @param  string  $sessionId
     * @param  bool  $administrator
     */
    private function __construct(

        /** Who the user is. */
        public string $id,

        /** The tenant the user is active in. */
        public string $tenantId,

        /** The session the request authenticated with. */
        public string $sessionId,

        /** Whether the user administers the tenant's single sign-on. */
        private bool $administrator,
    ) {}

    /**
     * A user of the tenant, on the session given.
     *
     * @param  string  $id
     * @param  string  $tenantId
     * @param  string  $sessionId
     * @param  bool  $administersSso
     * @return self
     */
    public static function of(string $id, string $tenantId, string $sessionId = 'session-0', bool $administersSso = false): self
    {
        return new self($id, $tenantId, $sessionId, $administersSso);
    }

    /**
     * Whether the user administers single sign-on for their active tenant.
     *
     * @return bool
     */
    public function administersSso(): bool
    {
        return $this->administrator;
    }

    /**
     * The name of the identifier.
     *
     * @return string
     */
    #[\Override]
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * The identifier.
     *
     * @return string
     */
    #[\Override]
    public function getAuthIdentifier(): string
    {
        return $this->id;
    }

    /**
     * The name of the password: the user has none.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * The password: the user has none.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPassword(): string
    {
        return '';
    }

    /**
     * The "remember me" token: the user has none.
     *
     * @return null
     */
    #[\Override]
    public function getRememberToken(): null
    {
        return null;
    }

    /**
     * Keep no "remember me" token.
     *
     * @param  mixed  $value
     * @return void
     */
    #[\Override]
    public function setRememberToken(mixed $value): void
    {
        unset($value);
    }

    /**
     * The name of the "remember me" token: the user has none.
     *
     * @return string
     */
    #[\Override]
    public function getRememberTokenName(): string
    {
        return '';
    }
}
