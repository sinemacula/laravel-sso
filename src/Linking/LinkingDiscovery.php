<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * What plain reads found before a completion took its locks, so it can lock in
 * order.
 *
 * It decides nothing: everything is judged again under the locks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkingDiscovery
{
    /**
     * Constructor.
     *
     * @param  bool  $locksDomain
     * @param  bool  $subjectHeld
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     */
    private function __construct(

        /** Whether the completion locks the claim of the linking email's domain. */
        public bool $locksDomain,

        /** Whether a row held the subject when it was read. */
        public bool $subjectHeld,

        /** The identity whose guard the completion takes first, if any. */
        public ?IdentityReference $identity,
    ) {}

    /**
     * Nothing about the completion touches linking.
     *
     * @return self
     */
    public static function notApplicable(): self
    {
        return new self(false, false, null);
    }

    /**
     * A row already holds the subject, so no guard or domain lock is needed.
     *
     * @return self
     */
    public static function subjectHeld(): self
    {
        return new self(false, true, null);
    }

    /**
     * The subject was absent, and the identity, if any, matched its email.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return self
     */
    public static function open(?IdentityReference $identity): self
    {
        return new self(true, false, $identity);
    }
}
