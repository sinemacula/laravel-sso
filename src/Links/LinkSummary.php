<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * What the link helpers return for one link (SSO-8.4): its id, the connection
 * it was made through with that connection's tenant and protocol, the issuer
 * and the subject's `NameID` format, its state, whether it was made by a
 * verified domain (SSO-8.8), and when it was created and last used.
 *
 * It never holds the subject: a list of an identity's links shows where they
 * sign in from, not who they are at the provider. It holds ids, names, flags
 * and times, never a secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkSummary implements \JsonSerializable
{
    /** @var string The form a time is encoded in: UTC, to the second. */
    private const string TIME_FORMAT = 'Y-m-d\TH:i:s\Z';

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  string  $issuer
     * @param  ?string  $nameIdFormat
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  bool  $domainProvenance
     * @param  \Carbon\CarbonImmutable  $createdAt
     * @param  ?\Carbon\CarbonImmutable  $lastUsedAt
     */
    public function __construct(

        /** The link's id, a lower-case ULID. */
        public string $id,

        /** The connection the link was made through. */
        public string $connectionId,

        /** The opaque id of the connection's tenant. */
        public string $tenantId,

        /** The connection's protocol. */
        public string $protocol,

        /** The identity provider's identifier, as received. */
        public string $issuer,

        /** The SAML `NameID` format; `null` for none. */
        public ?string $nameIdFormat,

        /** Whether the link resolves (active), is held for a redemption (reserved), or is suspended until confirmed. */
        public LinkState $state,

        /** Whether the link was made by a verified domain and not since confirmed. */
        public bool $domainProvenance,

        /** When the link was created. */
        public CarbonImmutable $createdAt,

        /** When the link last resolved a sign-in, to the minute; `null` for never. */
        public ?CarbonImmutable $lastUsedAt = null,
    ) {}

    /**
     * The summary of the link, made through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $link
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return self
     */
    public static function of(Link $link, Connection $connection): self
    {
        return new self(
            $link->id,
            $link->connection_id,
            $connection->tenant_id,
            $connection->protocol,
            $link->issuer,
            $link->name_id_format,
            $link->state,
            $link->domain_provenance,
            $link->created_at,
            $link->last_used_at,
        );
    }

    /**
     * The summary, with snake_case keys and each time as an ISO 8601 UTC
     * string. It holds no subject.
     *
     * @return array<string, bool|string|null>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'id'                => $this->id,
            'connection_id'     => $this->connectionId,
            'tenant_id'         => $this->tenantId,
            'protocol'          => $this->protocol,
            'issuer'            => $this->issuer,
            'name_id_format'    => $this->nameIdFormat,
            'state'             => $this->state->value,
            'domain_provenance' => $this->domainProvenance,
            'created_at'        => $this->createdAt->utc()->format(self::TIME_FORMAT),
            'last_used_at'      => $this->lastUsedAt?->utc()->format(self::TIME_FORMAT),
        ];
    }
}
