<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Identities;

/**
 * The authenticated person an action is taken for, as the application gives it.
 *
 * A missing session means none was supplied, never "the current one"; the
 * package reads no request or session itself.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Caller
{
    /** @var int The longest session id kept, in bytes. */
    public const int MAX_SESSION_ID_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity the person authenticated as. */
        public IdentityReference $identity,

        /** The session they are on, or `null` when none was supplied. */
        public ?string $sessionId = null,
    ) {
        if ($sessionId !== null && ($sessionId === '' || strlen($sessionId) > self::MAX_SESSION_ID_LENGTH)) {
            throw new \InvalidArgumentException(sprintf('A session id is 1 to %d bytes.', self::MAX_SESSION_ID_LENGTH));
        }
    }
}
