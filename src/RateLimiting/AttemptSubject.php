<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;

/**
 * An attempt at a limited flow and the raw values it counts against; a `null`
 * value is not counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttemptSubject
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @param  ?string  $ip
     * @param  ?string  $emailDomain
     * @param  ?string  $connection
     */
    private function __construct(

        /** The flow attempted. */
        public AttemptFlow $flow,

        /** The client's IP address, if there is a client. */
        public ?string $ip = null,

        /** The domain of the email given for discovery, if one was. */
        public ?string $emailDomain = null,

        /** The connection id, for a flow counted by connection. */
        public ?string $connection = null,
    ) {}

    /**
     * Starting an authorisation request.
     *
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $emailDomain
     * @return self
     */
    public static function authorizationRequest(ClientContext $client, ?string $emailDomain = null): self
    {
        return new self(AttemptFlow::AUTHORIZATION_REQUEST, ip: $client->ip, emailDomain: $emailDomain);
    }

    /**
     * A response at a connection's assertion consumer service or callback.
     *
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  string  $connection
     * @return self
     */
    public static function completion(ClientContext $client, string $connection): self
    {
        return new self(AttemptFlow::COMPLETION, ip: $client->ip, connection: $connection);
    }

    /**
     * Redeeming a handoff code.
     *
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return self
     */
    public static function redemption(ClientContext $client): self
    {
        return new self(AttemptFlow::REDEMPTION, ip: $client->ip);
    }

    /**
     * Importing or refreshing a connection's metadata or discovery document.
     *
     * @param  string  $connection
     * @return self
     */
    public static function metadata(string $connection): self
    {
        return new self(AttemptFlow::METADATA, connection: $connection);
    }

    /**
     * Checking the DNS record of one of a connection's domains.
     *
     * @param  string  $connection
     * @return self
     */
    public static function domainCheck(string $connection): self
    {
        return new self(AttemptFlow::DOMAIN_CHECK, connection: $connection);
    }

    /**
     * The non-null values of the flow's scopes, by scope.
     *
     * @return array<string, string>
     */
    public function counted(): array
    {
        $values = [
            AttemptScope::PER_IP->value           => $this->ip,
            AttemptScope::PER_EMAIL_DOMAIN->value => $this->emailDomain,
            AttemptScope::PER_CONNECTION->value   => $this->connection,
        ];

        $counted = [];

        foreach ($this->flow->scopes() as $scope) {

            $value = $values[$scope->value];

            if ($value === null) {
                continue;
            }

            $counted[$scope->value] = $value;
        }

        return $counted;
    }
}
