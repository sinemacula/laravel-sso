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
 * Under `laravel-iam` the type is the identity's morph class, as
 * `laravel-authentication`'s events give it (AUTH-9.4).
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

        /** The identity's type (under `laravel-iam`, its morph class). */
        public string $type,

        /** The identity's id. */
        public string $id,
    ) {
        if ($type === '' || $id === '') {
            throw new \InvalidArgumentException('An acting identity has a type and an id.');
        }
    }
}
