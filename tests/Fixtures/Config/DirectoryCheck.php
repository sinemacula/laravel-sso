<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Config;

use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * A composing package's check, added to the package's checker: it applies while
 * the package is in use, and finds a problem while `directory.revocation` is
 * unset.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DirectoryCheck implements ConfigurationCheck
{
    /**
     * It applies while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * Whether the directory's session revocation is set.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            static function (): void {
                if (config('directory.revocation') === null) {
                    throw new \LogicException('`directory.revocation` must be set.');
                }
            },
        ];
    }
}
