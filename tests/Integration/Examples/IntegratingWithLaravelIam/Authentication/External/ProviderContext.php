<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

/**
 * A stand-in for `laravel-authentication`'s `External\ProviderContext`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProviderContext
{
    /** @var int The most bytes the stored form may take. */
    public const int STORED_MAX_BYTES = 4096;

    /** @var array<string, mixed> The values, as given. */
    public array $values;

    /**
     * Constructor.
     *
     * @param  array<array-key, mixed>  $values
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(array $values)
    {
        $map = [];

        foreach ($values as $key => $value) {
            if (!is_string($key)) {
                throw new \InvalidArgumentException('A provider context must be a map with string keys.');
            }

            $map[$key] = $value;
        }

        $stored = $map === [] ? false : json_encode($map, JSON_PRESERVE_ZERO_FRACTION);

        if ($stored === false || strlen($stored) > self::STORED_MAX_BYTES) {
            throw new \InvalidArgumentException('A provider context must hold at least one value, and take at most 4096 bytes as stored.');
        }

        $this->values = $map;
    }

    /**
     * The values, as given.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->values;
    }
}
