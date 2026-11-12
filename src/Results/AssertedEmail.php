<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;

/**
 * An OIDC email and its `email_verified`, both from one source; informational
 * only, since only a `LinkingEmail` can link by email.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AssertedEmail implements \JsonSerializable
{
    /** @var int The longest email, in bytes. */
    public const int MAX_EMAIL_LENGTH = LinkingEmail::MAX_EMAIL_LENGTH;

    /** @var \SensitiveParameterValue The email, exactly as asserted. */
    private \SensitiveParameterValue $email;

    /**
     * Constructor.
     *
     * @param  string  $email
     * @param  ?bool  $verified
     * @param  \SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource  $source
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        // Held wrapped, so dumps and traces never show it
        #[\SensitiveParameter]
        string $email,

        /** `email_verified` if a JSON boolean, never coerced; else `null`. */
        public ?bool $verified,

        /** The source of the email and of `email_verified`. */
        public LinkingEmailSource $source,
    ) {
        StoredValues::assertText('asserted email', $email, self::MAX_EMAIL_LENGTH);

        $this->email = new \SensitiveParameterValue($email);
    }

    /**
     * A dump without the email.
     *
     * @return array{email: string, verified: ?bool, source: string}
     */
    public function __debugInfo(): array
    {
        return ['email' => StoredValues::REDACTED, 'verified' => $this->verified, 'source' => $this->source->value];
    }

    /**
     * Refuse to be serialised; only the verified result stores it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('An asserted email cannot be serialised.');
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
        throw new \LogicException('An asserted email cannot be unserialised.');
    }

    /**
     * The email, exactly as asserted.
     *
     * @return string
     */
    public function email(): string
    {
        /** @var string */
        return $this->email->getValue();
    }

    /**
     * The stored form, holding the email.
     *
     * @return array{email: string, verified: ?bool, source: string}
     */
    public function toArray(): array
    {
        return ['email' => $this->email(), 'verified' => $this->verified, 'source' => $this->source->value];
    }

    /**
     * The source and `email_verified`, never the email.
     *
     * @return array{source: string, verified: ?bool}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['source' => $this->source->value, 'verified' => $this->verified];
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
    public static function restore(#[\SensitiveParameter] array $stored): self
    {
        $verified = ($stored['verified'] ?? null) === null ? null : StoredValues::isTrue($stored, 'verified');

        return StoredValues::restoring(static fn (): self => new self(
            StoredValues::string($stored, 'email'),
            $verified,
            LinkingEmailSource::from(StoredValues::string($stored, 'source')),
        ));
    }
}
