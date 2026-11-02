<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkResolutionStatus;

/**
 * What a verified result's link resolved to (SSO-8.2, SSO-8.3, SSO-8.8), as
 * `Contracts\Linker::resolve()` answers it, in place of an identity or none, so
 * a suspended or reserved subject can never pass for an unlinked one:
 *
 * - `linked`: `$identity` is the identity it resolves to and `$linkId` the link
 *   that resolved it, whatever identifies a link in the linker's store. A link
 *   removed and made again has another id, so continuity is compared by it and
 *   never by the identity alone.
 * - `absent`: no link holds the subject. Only this lets a result be offered for
 *   provisioning, reserve a link or take an unlinked handoff.
 * - `reserved`: a live reservation holds the subject. It names nothing: a
 *   reservation never resolves a sign-in, and a result is refused rather than
 *   told whose it is.
 * - `suspended`: `$identity` is `null`, since it resolves nothing; `$holder`
 *   and `$linkId` say whose link it is, read only by a confirming `link`
 *   (SSO-8.8), never by a sign-in.
 *
 * It holds opaque references, never a subject or a secret.
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
    ) {}

    /**
     * An active link resolves the subject to the identity.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function linked(IdentityReference $identity, string $linkId): self
    {
        return new self(LinkResolutionStatus::LINKED, $identity, $identity, self::linkId($linkId));
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
     * Whether the link holding the subject is the identity's, active or
     * suspended, compared byte for byte.
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
