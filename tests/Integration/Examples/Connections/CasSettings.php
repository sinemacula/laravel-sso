<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Connections;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The CAS protocol's settings: one HTTPS `server_url`, which names the issuer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CasSettings implements ProtocolSettings
{
    /** @var string The CAS server's base URL. */
    public const string SERVER_URL = 'server_url';

    /**
     * Constructor.
     *
     * @param  array<array-key, mixed>  $values
     */
    private function __construct(

        /** The values as given. */
        private array $values,
    ) {}

    /**
     * The settings the values give.
     *
     * @param  array<array-key, mixed>  $values
     * @return static
     */
    #[\Override]
    public static function fromArray(array $values): static
    {
        return new self($values);
    }

    /**
     * No setting is a secret.
     *
     * @return list<string>
     */
    #[\Override]
    public static function secretNames(): array
    {
        return [];
    }

    /**
     * A change to the server may change what existing subjects mean.
     *
     * @return list<string>
     */
    #[\Override]
    public static function subjectNames(): array
    {
        return [self::SERVER_URL];
    }

    /**
     * The server names the issuer.
     *
     * @return list<string>
     */
    #[\Override]
    public static function issuerNames(): array
    {
        return [self::SERVER_URL];
    }

    /**
     * A change to the server is a trust change; there is no other setting.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    #[\Override]
    public static function freshnessFor(string $name): ?FreshnessOperation
    {
        return $name === self::SERVER_URL ? FreshnessOperation::CONNECTION_TRUST : null;
    }

    /**
     * The server, when one was given.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        return array_key_exists(self::SERVER_URL, $this->values) ? [self::SERVER_URL => $this->values[self::SERVER_URL]] : [];
    }

    /**
     * A missing server, or one not over HTTPS.
     *
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    #[\Override]
    public function violations(): array
    {
        $server = $this->values[self::SERVER_URL] ?? null;

        $code = match (true) {
            !is_string($server) || $server === '' => ViolationCode::REQUIRED,
            !str_starts_with($server, 'https://') => ViolationCode::NOT_HTTPS,
            default                               => null,
        };

        return $code === null ? [] : [new SettingViolation(self::SERVER_URL, $code)];
    }

    /**
     * Whether the server is set, over HTTPS.
     *
     * @return bool
     */
    #[\Override]
    public function isComplete(): bool
    {
        return $this->violations() === [];
    }

    /**
     * The server's base URL without a trailing `/`, or `null` while incomplete.
     *
     * @return ?string
     */
    public function serverUrl(): ?string
    {
        $server = $this->values[self::SERVER_URL] ?? null;

        return $this->isComplete() && is_string($server) ? rtrim($server, '/') : null;
    }
}
