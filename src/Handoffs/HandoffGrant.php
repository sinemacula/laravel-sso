<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * What a handoff code is issued for (SSO-9.2, SSO-9.9, SSO-9.10, SSO-2.13): the
 * verified result, which names the purpose, the application, the connection
 * and the request's public reference; the S256 challenge of the client's
 * verifier; the code's expiry; the connection's trust version, read from its
 * locked row as the code is issued, which the redemption compares with the
 * locked row's then, so a trust change between the two refuses the code
 * whichever store holds it; the identity the result's link resolved to, if
 * any; the identity a `link` or `reauthenticate` flow was started for, and the
 * session a `reauthenticate` flow was started on; the latest end of the
 * application's session the provider's deadline sets, where the deadline
 * contract says it limits the session, and `null` where it ignores it; the link
 * the result resolved to, so a link removed and made again is told apart; and
 * the reservation a result holding no link is bound to (SSO-8.8), which expires
 * exactly when the code does.
 *
 * The completion pipeline builds one and hands it to `Contracts\HandoffIssuer`;
 * the code is bound to every part of it. A grant whose identity or session does
 * not fit its purpose is the pipeline's mistake (`InvalidArgumentException`): a
 * `sign_in` grant names neither, a `link` grant names the identity only, and a
 * `reauthenticate` grant names both; a reservation belongs only to a `sign_in`
 * grant whose result resolved to no identity.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HandoffGrant
{
    /** @var int The longest session, link or reservation id, in bytes. */
    public const int MAX_ID_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Flows\S256Challenge  $challenge
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  int  $trustVersion
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @param  ?\Carbon\CarbonImmutable  $sessionNotAfter
     * @param  ?string  $linkId
     * @param  ?string  $reservationId
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The verified result the code carries. */
        public VerifiedResult $result,

        /** The S256 challenge of the verifier the code is redeemed with. */
        public S256Challenge $challenge,

        /** When the code expires. */
        public CarbonImmutable $expiresAt,

        /** The connection's trust version, read from its locked row at issuance. */
        public int $trustVersion,

        /** The identity the result's link resolved to at completion, if any. */
        public ?IdentityReference $linkedIdentity = null,

        /** The identity a `link` or `reauthenticate` flow was started for. */
        public ?IdentityReference $identity = null,

        /** The session a `reauthenticate` flow was started on. */
        public ?string $sessionId = null,

        /** The latest end of the application's session the provider's deadline sets. */
        public ?CarbonImmutable $sessionNotAfter = null,

        /** The link the result resolved to at completion, active or suspended, if any. */
        public ?string $linkId = null,

        /** The reservation the code is bound to, if any. */
        public ?string $reservationId = null,
    ) {
        self::assertBinding($result->purpose, $identity, $sessionId);

        if ($reservationId !== null && ($result->purpose !== Purpose::SIGN_IN || $linkedIdentity !== null)) {
            throw new \InvalidArgumentException('A reservation belongs only to a [sign_in] handoff grant that resolved to no identity.');
        }

        foreach (['session id' => $sessionId, 'link id' => $linkId, 'reservation id' => $reservationId] as $name => $value) {
            if (!self::isOptionalId($value)) {
                throw new \InvalidArgumentException(sprintf('A handoff grant\'s %s is 1 to %d bytes.', $name, self::MAX_ID_LENGTH));
            }
        }
    }

    /**
     * Whether the value is absent, or 1 to `MAX_ID_LENGTH` bytes.
     *
     * @param  ?string  $value
     * @return bool
     */
    private static function isOptionalId(?string $value): bool
    {
        return $value === null || ($value !== '' && strlen($value) <= self::MAX_ID_LENGTH);
    }

    /**
     * Refuse an identity or a session that does not fit the purpose.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertBinding(Purpose $purpose, ?IdentityReference $identity, ?string $sessionId): void
    {
        [$identityNamed, $sessionNamed, $what] = match ($purpose) {
            Purpose::SIGN_IN        => [false, false, 'no identity and no session'],
            Purpose::LINK           => [true, false, 'the identity and no session'],
            Purpose::REAUTHENTICATE => [true, true, 'the identity and the session'],
        };

        if (($identity !== null) !== $identityNamed || ($sessionId !== null) !== $sessionNamed) {
            throw new \InvalidArgumentException(sprintf('A [%s] handoff grant names %s.', $purpose->value, $what));
        }
    }
}
