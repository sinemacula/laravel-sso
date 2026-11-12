<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkResolutionStatus;

/**
 * What `Contracts\Linker::resolve()` answers, so a suspended or reserved
 * subject never passes for an unlinked one.
 *
 * Compare continuity by `$linkId`, never by identity alone: a link made again
 * has another id.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkResolution
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkResolutionStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $holder
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     */
    private function __construct(

        /** What it resolved to. */
        public LinkResolutionStatus $status,

        /** The identity an active link resolves to; `null` for every other status. */
        public ?IdentityReference $identity = null,

        /** Whose link holds the subject, active or suspended. */
        public ?IdentityReference $holder = null,

        /** The link that holds the subject, active or suspended. */
        public ?string $linkId = null,

        /** The active link's provenance at this resolution, when the linker states it. */
        public ?LinkOrigin $origin = null,
    ) {}

    /**
     * An active link resolves the subject to the identity.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function linked(IdentityReference $identity, string $linkId, ?LinkOrigin $origin = null): self
    {
        return new self(LinkResolutionStatus::LINKED, $identity, $identity, self::linkId($linkId), $origin);
    }

    /**
     * No link holds the subject.
     *
     * @return self
     */
    public static function absent(): self
    {
        return new self(LinkResolutionStatus::ABSENT);
    }

    /**
     * A live reservation holds the subject.
     *
     * @return self
     */
    public static function reserved(): self
    {
        return new self(LinkResolutionStatus::RESERVED);
    }

    /**
     * The holder's link holds the subject, suspended, and resolves nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $holder
     * @param  string  $linkId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function suspended(IdentityReference $holder, string $linkId): self
    {
        return new self(LinkResolutionStatus::SUSPENDED, holder: $holder, linkId: self::linkId($linkId));
    }

    /**
     * The holder's link could not be judged, so it resolves nothing this
     * attempt.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $holder
     * @param  string  $linkId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function scopeUnknown(IdentityReference $holder, string $linkId): self
    {
        return new self(LinkResolutionStatus::SCOPE_UNKNOWN, holder: $holder, linkId: self::linkId($linkId));
    }

    /**
     * Whether an active link resolves the subject.
     *
     * @return bool
     */
    public function isLinked(): bool
    {
        return $this->status === LinkResolutionStatus::LINKED;
    }

    /**
     * Whether no link holds the subject.
     *
     * @return bool
     */
    public function isAbsent(): bool
    {
        return $this->status === LinkResolutionStatus::ABSENT;
    }

    /**
     * Whether a live reservation holds the subject.
     *
     * @return bool
     */
    public function isReserved(): bool
    {
        return $this->status === LinkResolutionStatus::RESERVED;
    }

    /**
     * Whether a suspended link holds the subject.
     *
     * @return bool
     */
    public function isSuspended(): bool
    {
        return $this->status === LinkResolutionStatus::SUSPENDED;
    }

    /**
     * Whether the link holding the subject could not be judged, this attempt.
     *
     * @return bool
     */
    public function isScopeUnknown(): bool
    {
        return $this->status === LinkResolutionStatus::SCOPE_UNKNOWN;
    }

    /**
     * Whether the link holding the subject is the identity's, byte for byte.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    public function isHeldBy(IdentityReference $identity): bool
    {
        return $this->holder?->is($identity) ?? false;
    }

    /**
     * The link id, refused when it is empty or too long to bind to a code.
     *
     * @param  string  $linkId
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function linkId(string $linkId): string
    {
        if ($linkId === '' || strlen($linkId) > 255) {
            throw new \InvalidArgumentException('A link id is 1 to 255 bytes.');
        }

        return $linkId;
    }
}
