<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Identities;

/**
 * The authenticated person an action is taken for, as the application gives it:
 * their identity and, when the application supplies one, the session they are
 * on, an opaque id of 1 to 255 bytes. The package reads no request, job or
 * session to find either; whatever judges a caller (`Contracts\Freshness`,
 * `Contracts\LinkConfirmation`) judges the one it is given, and an
 * administration event names the identity as the one acting.
 *
 * No caller (`null` where one is taken) means no authenticated person, and a
 * caller with no session means none was supplied, never "the current one": a
 * contract that cannot judge a caller without its session answers as it does
 * when it cannot tell.
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
