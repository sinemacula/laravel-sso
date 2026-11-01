<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;

/**
 * The linking email of a verified result (SSO-8.1, SSO-8.8): the address the
 * protocol itself asserted, never one read through attribute mapping, with
 * where it came from and the organisation claim's value it was accepted under
 * for an issuer shared by many organisations (Google's `hd`, say). It is kept
 * apart from the mapped attributes, and only linking by a verified domain reads
 * it.
 *
 * The email is 3 to 320 bytes with one `@` between a non-empty local part and a
 * non-empty domain; it is kept exactly as asserted, and the application's
 * normaliser, never the package, decides how it compares. The organisation is 1
 * to 255 bytes when given.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkingEmail
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

        /** The organisation claim's value the email was accepted under, for a shared issuer. */
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
     * The linking email as stored, with snake_case keys.
     *
     * @return array{email: string, source: string, organization: ?string}
     */
    public function toArray(): array
    {
        return ['email' => $this->email, 'source' => $this->source->value, 'organization' => $this->organization];
    }

    /**
     * The linking email `toArray()` stored, read back from the package's own
     * storage; never from client input.
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
