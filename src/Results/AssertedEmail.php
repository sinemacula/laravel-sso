<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;

/**
 * The email a provider asserted with its `email_verified`, carried together
 * from the one source they came from (SSO-7.7): the validated ID token or a
 * validated UserInfo response whose `sub` matched it, never one from each.
 *
 * `email_verified` is carried exactly as asserted when it is a JSON boolean:
 * `true` or `false`. It is `null` when the source gave no boolean (absent,
 * `null`, a string such as `"true"`, a number, an object or an array), which is
 * unknown, never coerced and never read as false. It is informational: only a
 * `LinkingEmail` lets a link be made by email (SSO-8.8).
 *
 * The email is 1 to 320 bytes and kept exactly as asserted, never trimmed or
 * normalised, and need not be well formed. It is a provider's value, so it is
 * held in a `\SensitiveParameterValue` behind `email()`: a dump shows it as
 * `[redacted]`, `json_encode()`, and a logger's normaliser that falls back to
 * it, write only the source and `email_verified`, and it refuses to be
 * serialised or unserialised. `toArray()` is the stored form, holding the
 * email, for the verified result's encrypted handoff (SSO-8.1).
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

        // The email, exactly as asserted; held wrapped
        #[\SensitiveParameter]
        string $email,

        /** The source's `email_verified`, when it is a JSON boolean; `null` when it stated none. */
        public ?bool $verified,

        /** The source of the email and of `email_verified`. */
        public LinkingEmailSource $source,
    ) {
        StoredValues::assertText('asserted email', $email, self::MAX_EMAIL_LENGTH);

        $this->email = new \SensitiveParameterValue($email);
    }

    /**
     * What a dump shows: `email_verified` and the source, never the email.
     *
     * @return array{email: string, verified: ?bool, source: string}
     */
    public function __debugInfo(): array
    {
        return ['email' => StoredValues::REDACTED, 'verified' => $this->verified, 'source' => $this->source->value];
    }

    /**
     * Refuse to be serialised: only the verified result stores it, through
     * `toArray()`.
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
     * The asserted email as stored, with snake_case keys.
     *
     * @return array{email: string, verified: ?bool, source: string}
     */
    public function toArray(): array
    {
        return ['email' => $this->email(), 'verified' => $this->verified, 'source' => $this->source->value];
    }

    /**
     * What `json_encode()` writes: the source and `email_verified`, never the
     * email.
     *
     * @return array{source: string, verified: ?bool}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['source' => $this->source->value, 'verified' => $this->verified];
    }

    /**
     * The asserted email `toArray()` stored, read back from the package's own
     * storage; never from client input.
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
