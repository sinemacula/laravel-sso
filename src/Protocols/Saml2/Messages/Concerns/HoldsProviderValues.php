<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns;

/**
 * Holds identity provider values so only accessors reveal them: dumps, casts
 * and JSON show `[redacted]`, and serialising throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait HoldsProviderValues
{
    /** @var \SensitiveParameterValue What the provider asserted, by name. */
    private readonly \SensitiveParameterValue $values;

    /**
     * Show no value in a dump.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['values' => '[redacted]'];
    }

    /**
     * Refuse to be serialised; the value lives only for its completion.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException(sprintf('A %s cannot be serialised.', self::class));
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException(sprintf('A %s cannot be unserialised.', self::class));
    }

    /**
     * Encode no value.
     *
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * Hold the values, once, from the constructor.
     *
     * @param  array<string, mixed>  $values
     * @return void
     */
    private function hold(#[\SensitiveParameter] array $values): void
    {
        $this->values = new \SensitiveParameterValue($values);
    }

    /**
     * The value held under the name, or `null` when none is.
     *
     * @param  string  $name
     * @return mixed
     */
    private function held(string $name): mixed
    {
        /** @var array<string, mixed> $values */
        $values = $this->values->getValue();

        return $values[$name] ?? null;
    }
}
