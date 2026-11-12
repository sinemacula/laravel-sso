<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Protocols\Navigation;

/**
 * Reads where a start sends the browser, from any form a test holds it in. A
 * refused start throws, so the test fails there rather than further on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Navigations
{
    /**
     * The navigation's URL and posted fields, none for a redirect.
     *
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Sso\Flows\StartResult|\SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @return array{0: string, 1: array<array-key, mixed>}
     *
     * @throws \LogicException
     */
    public static function parts(array|Navigation|StartResult $navigation): array
    {
        if (is_array($navigation)) {
            return self::decoded(is_array($navigation['navigation'] ?? null) ? $navigation['navigation'] : $navigation);
        }

        $navigation = $navigation instanceof StartResult ? self::of($navigation) : $navigation;

        return [$navigation->url(), $navigation->fields()];
    }

    /**
     * The navigation's URL; a string is returned as is.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult|\SineMacula\Laravel\Sso\Protocols\Navigation|string  $navigation
     * @return string
     *
     * @throws \LogicException
     */
    public static function url(Navigation|StartResult|string $navigation): string
    {
        return is_string($navigation) ? $navigation : self::parts($navigation)[0];
    }

    /**
     * The URL and fields of a JSON-decoded navigation, each empty when missing.
     *
     * @param  array<array-key, mixed>  $navigation
     * @return array{0: string, 1: array<array-key, mixed>}
     */
    private static function decoded(array $navigation): array
    {
        $url    = $navigation['url']    ?? null;
        $fields = $navigation['fields'] ?? null;

        return [is_string($url) ? $url : '', is_array($fields) ? $fields : []];
    }

    /**
     * The navigation of a started flow.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Protocols\Navigation
     *
     * @throws \LogicException
     */
    private static function of(StartResult $start): Navigation
    {
        return $start->navigation ?? throw new \LogicException(sprintf('The flow did not start: it was refused with [%s].', $start->reason?->value));
    }
}
