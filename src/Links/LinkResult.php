<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a link's removal ended (SSO-8.4, SSO-4.5): `removed`, with the summary of
 * the link as it was; or `refused`, with `link_not_found` or
 * `freshness_required`.
 *
 * A refusal is a value, never thrown, and changed nothing: no link was deleted,
 * no session revocation asked for and no event dispatched. `link_not_found` is
 * the same for a link that does not exist and for another identity's, so a
 * caller learns nothing of links that are not its own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkResult implements \JsonSerializable
{
    /** @var list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason> The reasons a removal is refused for. */
    private const array REFUSALS = [
        FailureReason::LINK_NOT_FOUND,
        FailureReason::FRESHNESS_REQUIRED,
    ];

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Links\LinkSummary  $link
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The link removed, as it was, for a removal only. */
        public ?LinkSummary $link = null,

        /** Why the removal was refused, for a refusal only. */
        public ?FailureReason $reason = null,
    ) {}

    /**
     * The link was removed and the identity's sessions through its connection
     * revoked.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkSummary  $link
     * @return self
     */
    public static function removed(LinkSummary $link): self
    {
        return new self($link);
    }

    /**
     * The removal was refused for the reason given: `link_not_found` or
     * `freshness_required`.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason): self
    {
        if (!in_array($reason, self::REFUSALS, true)) {
            throw new \InvalidArgumentException(sprintf('A link\'s removal is not refused for [%s].', $reason->value));
        }

        return new self(reason: $reason);
    }

    /**
     * Whether the link was removed.
     *
     * @return bool
     */
    public function isRemoved(): bool
    {
        return $this->reason === null;
    }

    /**
     * Whether the removal was refused, with a reason.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->reason !== null;
    }

    /**
     * The result, with snake_case keys: whether the link was removed, the link
     * and the reason.
     *
     * @return array{removed: bool, link: ?array<string, mixed>, reason: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'removed' => $this->isRemoved(),
            'link'    => $this->link?->jsonSerialize(),
            'reason'  => $this->reason?->value,
        ];
    }
}
