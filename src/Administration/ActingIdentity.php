<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Administration;

/**
 * The identity acting through a management helper (SSO-1.2, SSO-10.4), as the
 * application passes it: a type and an id, each an opaque string, carried on
 * the administration event the helper dispatches. Who may manage a connection
 * is the application's authorisation, never the package's; the package only
 * reports who did.
 *
 * For an Eloquent identity the type is its morph class, as the application's
 * authentication events give it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ActingIdentity
{
    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  string  $id
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity's type (for an Eloquent identity, its morph class). */
        public string $type,

        /** The identity's id. */
        public string $id,
    ) {
        if ($type === '' || $id === '') {
            throw new \InvalidArgumentException('An acting identity has a type and an id.');
        }
    }
}
