<?php

declare(strict_types = 1);

namespace Tests\Unit\Config\Fixtures;

use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * A check that applies and finds two problems among three checks, of two
 * exception types.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FailingCheck implements ConfigurationCheck
{
    /**
     * It applies.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * A failing check, a passing one, and another failing one.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            static function (): void {
                throw new \InvalidArgumentException('`sso.example.first` must be set.');
            },
            static fn (): bool => true,
            static function (): void {
                throw new \RuntimeException('The PHP extension `example` is not loaded.');
            },
        ];
    }
}
