<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How an import of an OpenID provider's discovery document ended (SSO-2.8,
 * SSO-2.11): proposed, with the settings it proposes; refused, with the reason;
 * or rate limited, with the seconds until another import of the connection may
 * be tried.
 *
 * A refusal is `protocol_unavailable` (OIDC is not available),
 * `settings_invalid` (an issuer that is not a valid setting),
 * `connection_not_found` (an unknown connection, another tenant's, or one that
 * is not OIDC), `fetch_refused` or `fetch_failed` (the discovery document or
 * the JWKS, whose detail goes only to the logs), `issuer_mismatch`,
 * `discovery_invalid` or `jwks_invalid`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DiscoveryImport
{
    /** @var list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason> The reasons an import is refused for. */
    public const array REFUSALS = [
        FailureReason::PROTOCOL_UNAVAILABLE,
        FailureReason::SETTINGS_INVALID,
        FailureReason::CONNECTION_NOT_FOUND,
        FailureReason::FETCH_REFUSED,
        FailureReason::FETCH_FAILED,
        FailureReason::ISSUER_MISMATCH,
        FailureReason::DISCOVERY_INVALID,
        FailureReason::JWKS_INVALID,
    ];

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings  $proposed
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** The settings the document proposes, for a proposed import. */
        public ?ProposedOidcSettings $proposed = null,

        /** Why it was refused or limited, for one that was. */
        public ?FailureReason $reason = null,

        /** Seconds, at least 1, until it may be tried again, for a rate limited one. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * The document was read and proposes the settings.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\ProposedOidcSettings  $proposed
     * @return self
     */
    public static function proposed(ProposedOidcSettings $proposed): self
    {
        return new self($proposed);
    }

    /**
     * The import was refused for the reason.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason): self
    {
        if (!in_array($reason, self::REFUSALS, true)) {
            throw new \InvalidArgumentException(sprintf('A discovery import is not refused for [%s].', $reason->value));
        }

        return new self(reason: $reason);
    }

    /**
     * Too many imports of the connection were tried.
     *
     * @param  int  $retryAfter
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function rateLimited(int $retryAfter): self
    {
        if ($retryAfter < 1) {
            throw new \InvalidArgumentException('A rate limited discovery import may be tried again after at least 1 second.');
        }

        return new self(reason: FailureReason::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * Whether the document was read and proposes settings.
     *
     * @return bool
     *
     * @phpstan-assert-if-true !null $this->proposed
     */
    public function isProposed(): bool
    {
        return $this->proposed !== null;
    }

    /**
     * Whether the import was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->proposed === null && $this->reason !== FailureReason::RATE_LIMITED;
    }

    /**
     * Whether too many imports of the connection were tried.
     *
     * @return bool
     */
    public function isRateLimited(): bool
    {
        return $this->reason === FailureReason::RATE_LIMITED;
    }
}
