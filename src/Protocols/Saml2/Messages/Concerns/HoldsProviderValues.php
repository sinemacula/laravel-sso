<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns;

/**
 * Holds what an identity provider asserted, as the SAML adapter read it from a
 * verified element, so none of it leaves the value but through its accessors
 * (SSO-9.8, SSO-11.9): the values live in one `\SensitiveParameterValue`, so a
 * dump, by PHP's own functions or by the VarDumper behind Laravel's helpers
 * (which also lists private properties), an array cast and `json_encode()` show
 * `[redacted]`, and the value refuses to be serialised or unserialised, so it
 * never reaches a queue, a cache, a log or an event.
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
     * What a dump shows: never a value.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['values' => '[redacted]'];
    }

    /**
     * Refuse to be serialised: the value lives only for the completion that
     * read it.
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
     * What `json_encode()` writes: never a value.
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
