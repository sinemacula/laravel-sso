<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Support\Facades\Auth as IlluminateAuth;

/**
 * A stand-in for `laravel-authentication`'s `Auth` facade; `sessions()`
 * reaches the default guard, which a test makes `ExternalGuard`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @method static \Tests\Integration\Examples\IntegratingWithLaravelIam\ExternalSessions sessions()
 *
 * @internal
 */
final class Auth extends IlluminateAuth {}
