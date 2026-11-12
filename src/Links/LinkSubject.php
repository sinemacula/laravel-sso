<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * What a link is keyed by within its connection: issuer, subject and `NameID`
 * format, byte for byte as received.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkSubject
{
    /** @var int The longest issuer, in bytes. */
    public const int MAX_ISSUER_LENGTH = 1024;

    /** @var int The longest subject, in bytes. */
    public const int MAX_SUBJECT_LENGTH = 1024;

    /** @var int The longest NameID format, in bytes. */
    public const int MAX_NAME_ID_FORMAT_LENGTH = 255;

    /** @var string The tag the key's input starts with, naming its layout. */
    private const string KEY_VERSION = 'sso-link-v1';

    /**
     * Constructor.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $nameIdFormat
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity provider's identifier, as received. */
        public string $issuer,

        /** The person's stable identifier at the provider, byte for byte. */
        public string $subject,

        /** The SAML `NameID` format, part of the subject; `null` for none. */
        public ?string $nameIdFormat = null,
    ) {
        self::assertBytes('issuer', $issuer, self::MAX_ISSUER_LENGTH);
        self::assertBytes('subject', $subject, self::MAX_SUBJECT_LENGTH);

        if ($nameIdFormat === null) {
            return;
        }

        self::assertBytes('NameID format', $nameIdFormat, self::MAX_NAME_ID_FORMAT_LENGTH);
    }

    /**
     * The subject a verified result names: its issuer, subject and format.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return self
     */
    public static function of(VerifiedResult $result): self
    {
        return new self($result->issuer, $result->subject, $result->nameIdFormat);
    }

    /**
     * The stored `subject_key`, hashed from length-prefixed parts so no
     * collation can fold a subject and no two triples collide.
     *
     * @return string
     */
    public function key(): string
    {
        $format = $this->nameIdFormat === null ? 'N' : 'F' . self::prefixed($this->nameIdFormat);

        return hash('sha256', self::KEY_VERSION . "\0" . self::prefixed($this->issuer) . $format . self::prefixed($this->subject));
    }

    /**
     * Whether the other subject is this one, byte for byte.
     *
     * @param  self  $other
     * @return bool
     */
    public function is(self $other): bool
    {
        return $this->issuer       === $other->issuer
            && $this->nameIdFormat === $other->nameIdFormat
            && $this->subject      === $other->subject;
    }

    /**
     * The value, prefixed with its length in bytes as a 32-bit big-endian
     * integer.
     *
     * @param  string  $value
     * @return string
     */
    private static function prefixed(string $value): string
    {
        return pack('N', strlen($value)) . $value;
    }

    /**
     * Refuse a value that is empty or longer than the bytes allowed.
     *
     * @param  string  $name
     * @param  string  $value
     * @param  int  $maxBytes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertBytes(string $name, string $value, int $maxBytes): void
    {
        if ($value === '' || strlen($value) > $maxBytes) {
            throw new \InvalidArgumentException(sprintf('A link\'s %s is 1 to %d bytes.', $name, $maxBytes));
        }
    }
}
