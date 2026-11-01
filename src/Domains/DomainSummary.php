<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * What a helper returns for one of a connection's domains (SSO-3.1 to SSO-3.3):
 * its id, connection, normalised domain and state; the name the TXT record is
 * looked up at (`recordName`, `_sso-verification.example.com`); when it was
 * claimed and when a pending claim expires; when it became verified and last
 * passed a check; when linking by it was suspended and when it lapses, once a
 * recheck found its record gone; and when it lapsed.
 *
 * The token the record must carry is for the administrator to publish, so it is
 * read only through `verificationToken()`. It is held in a
 * `\SensitiveParameterValue`, shown in no dump, left out of `json_encode()`,
 * and the summary refuses to be serialised or unserialised, so it never reaches
 * a log, a queue or an event by accident.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainSummary implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The token the TXT record must carry, a `string`. */
    private \SensitiveParameterValue $token;

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $connectionId
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\DomainState  $state
     * @param  string  $recordName
     * @param  string  $verificationToken
     * @param  \Carbon\CarbonImmutable  $claimedAt
     * @param  ?\Carbon\CarbonImmutable  $pendingExpiresAt
     * @param  ?\Carbon\CarbonImmutable  $verifiedAt
     * @param  ?\Carbon\CarbonImmutable  $lastSuccessfulCheckAt
     * @param  ?\Carbon\CarbonImmutable  $linkingSuspendedAt
     * @param  ?\Carbon\CarbonImmutable  $lapsesAt
     * @param  ?\Carbon\CarbonImmutable  $lapsedAt
     */
    public function __construct(

        /** The claim's id. */
        public string $id,

        /** The connection that claimed it. */
        public string $connectionId,

        /** The domain, normalised: lower-case ASCII, no trailing dot. */
        public string $domain,

        /** Where the claim stands. */
        public DomainState $state,

        /** The name the TXT record is looked up at. */
        public string $recordName,

        // Not promoted: held wrapped, so no dump, export or array cast shows it
        #[\SensitiveParameter]
        string $verificationToken,

        /** When it was claimed. */
        public CarbonImmutable $claimedAt,

        /** When the claim expires, while it is pending. */
        public ?CarbonImmutable $pendingExpiresAt = null,

        /** When it became verified, while it is verified. */
        public ?CarbonImmutable $verifiedAt = null,

        /** When it last passed a check. */
        public ?CarbonImmutable $lastSuccessfulCheckAt = null,

        /** When a recheck found its record gone and suspended linking by it. */
        public ?CarbonImmutable $linkingSuspendedAt = null,

        /** When it lapses unless a check succeeds first. */
        public ?CarbonImmutable $lapsesAt = null,

        /** When it lapsed, while it is lapsed. */
        public ?CarbonImmutable $lapsedAt = null,
    ) {
        $this->token = new \SensitiveParameterValue($verificationToken);
    }

    /**
     * What a dump shows: everything but the token.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [...$this->jsonSerialize(), 'verification_token' => '[redacted]'];
    }

    /**
     * Refuse to be serialised: the summary carries the token.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A domain summary cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A domain summary cannot be unserialised.');
    }

    /**
     * The summary of the claim.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return self
     */
    public static function of(Domain $domain): self
    {
        return new self(
            id: $domain->id,
            connectionId: $domain->connection_id,
            domain: $domain->domain,
            state: $domain->state,
            recordName: DomainStanding::lookupName($domain),
            verificationToken: $domain->verification_token,
            claimedAt: $domain->claimed_at,
            pendingExpiresAt: $domain->pending_expires_at,
            verifiedAt: $domain->verified_at,
            lastSuccessfulCheckAt: $domain->last_successful_check_at,
            linkingSuspendedAt: $domain->linking_suspended_at,
            lapsesAt: $domain->lapses_at,
            lapsedAt: $domain->lapsed_at,
        );
    }

    /**
     * The value the TXT record at `recordName` must hold, exactly, for the
     * domain to be verified.
     *
     * @return string
     */
    public function verificationToken(): string
    {
        $token = $this->token->getValue();

        assert(is_string($token));

        return $token;
    }

    /**
     * Whether the domain is verified for its connection.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->state === DomainState::VERIFIED;
    }

    /**
     * The summary, with snake_case keys and each time as an ISO 8601 UTC
     * string; never the token, which `verificationToken()` gives.
     *
     * @return array<string, ?string>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'id'                       => $this->id,
            'connection_id'            => $this->connectionId,
            'domain'                   => $this->domain,
            'state'                    => $this->state->value,
            'record_name'              => $this->recordName,
            'claimed_at'               => self::time($this->claimedAt),
            'pending_expires_at'       => self::time($this->pendingExpiresAt),
            'verified_at'              => self::time($this->verifiedAt),
            'last_successful_check_at' => self::time($this->lastSuccessfulCheckAt),
            'linking_suspended_at'     => self::time($this->linkingSuspendedAt),
            'lapses_at'                => self::time($this->lapsesAt),
            'lapsed_at'                => self::time($this->lapsedAt),
        ];
    }

    /**
     * The instant as an ISO 8601 UTC string, or `null`.
     *
     * @param  ?\Carbon\CarbonImmutable  $time
     * @return ?string
     */
    private static function time(?CarbonImmutable $time): ?string
    {
        return $time?->utc()->format('Y-m-d\TH:i:s\Z');
    }
}
