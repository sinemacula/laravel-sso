<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;

/**
 * One attempt at a limited flow (SSO-11.8) and what it is counted against: the
 * client's IP address, the email domain an authorisation request gave for
 * discovery, and the connection, whichever the flow counts. Built only through
 * the named constructor of its flow, so it names nothing its flow does not
 * count. A `null` IP address or email domain is not counted (a console caller
 * has no client); the connection of a flow counted by connection is always
 * given.
 *
 * Values are passed as received; the limiter brings each to the form it counts
 * in (an IPv4-mapped IPv6 address as its IPv4 address, a domain in lower case).
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

        /** The id of the connection attempted through, for a flow counted by connection. */
        public ?string $connection = null,
    ) {}

    /**
     * Starting an authorisation request, from the IP address and, for
     * discovery, with the email's domain.
     *
     * @param  ?string  $ip
     * @param  ?string  $emailDomain
     * @return self
     */
    public static function authorizationRequest(?string $ip, ?string $emailDomain = null): self
    {
        return new self(AttemptFlow::AUTHORIZATION_REQUEST, ip: $ip, emailDomain: $emailDomain);
    }

    /**
     * A response at a connection's assertion consumer service or callback, from
     * the IP address.
     *
     * @param  ?string  $ip
     * @param  string  $connection
     * @return self
     */
    public static function completion(?string $ip, string $connection): self
    {
        return new self(AttemptFlow::COMPLETION, ip: $ip, connection: $connection);
    }

    /**
     * Redeeming a handoff code, from the IP address.
     *
     * @param  ?string  $ip
     * @return self
     */
    public static function redemption(?string $ip): self
    {
        return new self(AttemptFlow::REDEMPTION, ip: $ip);
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
     * What the attempt is counted against, by scope: each scope of its flow
     * whose value was given.
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
