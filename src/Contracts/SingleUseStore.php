<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * Records a key once in its namespace until an expiry, atomically across every
 * server, and answers whether it was new.
 *
 * Record within the caller's transaction, so a rolled-back redemption can be
 * retried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SingleUseStore
{
    /**
     * Answer `seen` only when the key is known to be held; throw on any doubt.
     * The key may be a secret, so keep only a digest of it.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function record(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until): SingleUseOutcome;
}
