<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use SineMacula\Laravel\Sso\Http\ClientContext;

/**
 * The clients the examples take actions for, where an application's controller
 * would build one from its request (`ClientContext::fromRequest()`): a browser,
 * with an IP address and a user agent, which every attempt counts against and
 * every event carries, and no client at all, as the console, a queued job and
 * the schedule pass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Clients
{
    /** @var string The IP address the browser comes from. */
    public const string IP = '203.0.113.7';

    /** @var string The user agent the browser sends. */
    public const string USER_AGENT = 'Example/1.0';

    /**
     * Disallow instantiation; factory only.
     */
    private function __construct() {}

    /**
     * The browser a test's action is taken for.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    public static function browser(): ClientContext
    {
        return new ClientContext(self::IP, self::USER_AGENT);
    }

    /**
     * No client: the context work with no request takes.
     *
     * @return \SineMacula\Laravel\Sso\Http\ClientContext
     */
    public static function none(): ClientContext
    {
        return new ClientContext(null, null);
    }
}
