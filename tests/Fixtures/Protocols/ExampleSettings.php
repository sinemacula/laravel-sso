<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Protocols;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The settings of the example protocol: an `issuer`, which is trust and
 * subject, and is required; an `api_secret`, a secret; anything else kept as
 * given, with no operation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExampleSettings implements ProtocolSettings
{
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
     * The secret settings.
     *
     * @return list<string>
     */
    #[\Override]
    public static function secretNames(): array
    {
        return ['api_secret'];
    }

    /**
     * The settings a change to which alters subjects.
     *
     * @return list<string>
     */
    #[\Override]
    public static function subjectNames(): array
    {
        return ['issuer'];
    }

    /**
     * The issuer is trust; nothing else needs freshness.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    #[\Override]
    public static function freshnessFor(string $name): ?FreshnessOperation
    {
        return $name === 'issuer' ? FreshnessOperation::CONNECTION_TRUST : null;
    }

    /**
     * The values as given.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        $values = [];

        foreach ($this->values as $name => $value) {
            $values[(string) $name] = $value;
        }

        return $values;
    }

    /**
     * A missing or empty issuer.
     *
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    #[\Override]
    public function violations(): array
    {
        return $this->isComplete() ? [] : [new SettingViolation('issuer', ViolationCode::REQUIRED)];
    }

    /**
     * Whether the issuer is a non-empty string.
     *
     * @return bool
     */
    #[\Override]
    public function isComplete(): bool
    {
        return is_string($this->values['issuer'] ?? null) && $this->values['issuer'] !== '';
    }
}
