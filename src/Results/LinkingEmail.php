<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;

/**
 * The email the protocol itself asserted, for linking by a verified domain;
 * kept exactly as asserted and redacted from JSON.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkingEmail implements \JsonSerializable
{
    /** @var int The longest email, in bytes. */
    public const int MAX_EMAIL_LENGTH = 320;

    /** @var int The longest organisation claim value, in bytes. */
    public const int MAX_ORGANIZATION_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  string  $email
     * @param  \SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource  $source
     * @param  ?string  $organization
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The email, exactly as asserted. */
        public string $email,

        /** Where the email came from. */
        public LinkingEmailSource $source,

        /** The organisation claim value (Google's `hd`) for a shared issuer. */
        public ?string $organization = null,
    ) {
        StoredValues::assertText('linking email', $email, self::MAX_EMAIL_LENGTH);
        StoredValues::assertOptionalText('organisation', $organization, self::MAX_ORGANIZATION_LENGTH);

        if (preg_match('/^[^@]+@[^@]+$/D', $email) !== 1) {
            throw new \InvalidArgumentException('A linking email has one `@` between a local part and a domain.');
        }
    }

    /**
     * The email's domain, after its `@`, exactly as asserted.
     *
     * @return string
     */
    public function domain(): string
    {
        return substr($this->email, (int) strrpos($this->email, '@') + 1);
    }

    /**
     * The stored form, holding every value.
     *
     * @return array{email: string, source: string, organization: ?string}
     */
    public function toArray(): array
    {
        return ['email' => $this->email, 'source' => $this->source->value, 'organization' => $this->organization];
    }

    /**
     * The source, with the email and any organisation redacted.
     *
     * @return array{email: string, source: string, organization: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['email' => StoredValues::REDACTED, 'source' => $this->source->value, 'organization' => StoredValues::redacted($this->organization)];
    }

    /**
     * Restore `toArray()` output from package storage, never client input.
     *
     * @param  array<array-key, mixed>  $stored
     * @return self
     *
     * @throws \UnexpectedValueException
     *
     * @internal
     */
    public static function restore(array $stored): self
    {
        return StoredValues::restoring(static fn (): self => new self(
            StoredValues::string($stored, 'email'),
            LinkingEmailSource::from(StoredValues::string($stored, 'source')),
            StoredValues::optionalString($stored, 'organization'),
        ));
    }
}
