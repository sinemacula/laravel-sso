<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Links;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;

/**
 * What a test's linker answers: the identity it resolves to through a link
 * whose id is `linkId()` of that identity, stable across every call, or absent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExampleLinks
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The resolution of the identity, or an absent link for none.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     */
    public static function resolution(?IdentityReference $identity): LinkResolution
    {
        return $identity === null ? LinkResolution::absent() : LinkResolution::linked($identity, self::linkId($identity));
    }

    /**
     * The id of the identity's link.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return string
     */
    public static function linkId(IdentityReference $identity): string
    {
        return 'link-' . $identity->id;
    }
}
