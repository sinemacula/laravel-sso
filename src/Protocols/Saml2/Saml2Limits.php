<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The caps and windows every SAML connection is held to (SSO-6.1, SSO-6.5),
 * read from `sso.saml2` on each call, so nothing is kept across requests
 * (SSO-11.2), each failing closed with an `InvalidArgumentException` naming its
 * key when it is malformed; `[saml2]` reports the same at boot.
 *
 * - `max_response_bytes`: the longest posted `SAMLResponse`, still base64
 *   encoded, 16 KiB to 1 MiB (default 256 KiB), checked before it is decoded.
 * - `max_xml_bytes`: the longest decoded response, 16 KiB to 1 MiB (default 192
 *   KiB), checked before it is parsed.
 * - `max_decrypted_bytes`: the longest assertion decrypted from an
 *   `EncryptedAssertion`, 4 KiB to 1 MiB (default 128 KiB), checked before it
 *   is parsed.
 * - `issue_instant_max_age_seconds`: how old a response's and an assertion's
 *   `IssueInstant` may be, 30 seconds to an hour (default 300), the clock skew
 *   allowed on top.
 *
 * The clock skew itself is `sso.clock.skew_seconds` (`Clock\ClockSkew`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Saml2Limits
{
    /** @var int The longest encoded response when none is configured, in bytes. */
    public const int DEFAULT_MAX_RESPONSE_BYTES = 262144;

    /** @var int The longest decoded response when none is configured, in bytes. */
    public const int DEFAULT_MAX_XML_BYTES = 196608;

    /** @var int The longest decrypted assertion when none is configured, in bytes. */
    public const int DEFAULT_MAX_DECRYPTED_BYTES = 131072;

    /** @var int The oldest `IssueInstant` accepted when none is configured, in seconds. */
    public const int DEFAULT_ISSUE_INSTANT_MAX_AGE_SECONDS = 300;

    /** @var int The smallest cap on an encoded or decoded response, in bytes. */
    public const int MIN_MESSAGE_BYTES = 16384;

    /** @var int The smallest cap on a decrypted assertion, in bytes. */
    public const int MIN_DECRYPTED_BYTES = 4096;

    /** @var int The largest cap on any of them, in bytes. */
    public const int MAX_BYTES = 1048576;

    /** @var int The smallest `IssueInstant` maximum age, in seconds. */
    public const int MIN_ISSUE_INSTANT_MAX_AGE_SECONDS = 30;

    /** @var int The largest `IssueInstant` maximum age, in seconds. */
    public const int MAX_ISSUE_INSTANT_MAX_AGE_SECONDS = 3600;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the limits are read from. */
        private Repository $config,
    ) {}

    /**
     * The longest posted `SAMLResponse`, still encoded, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxResponseBytes(): int
    {
        return IntegerSetting::read($this->config, 'sso.saml2.max_response_bytes', self::DEFAULT_MAX_RESPONSE_BYTES, self::MIN_MESSAGE_BYTES, self::MAX_BYTES);
    }

    /**
     * The longest decoded response, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxXmlBytes(): int
    {
        return IntegerSetting::read($this->config, 'sso.saml2.max_xml_bytes', self::DEFAULT_MAX_XML_BYTES, self::MIN_MESSAGE_BYTES, self::MAX_BYTES);
    }

    /**
     * The longest decrypted assertion, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxDecryptedBytes(): int
    {
        return IntegerSetting::read($this->config, 'sso.saml2.max_decrypted_bytes', self::DEFAULT_MAX_DECRYPTED_BYTES, self::MIN_DECRYPTED_BYTES, self::MAX_BYTES);
    }

    /**
     * How old an `IssueInstant` may be, in seconds, before the clock skew.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function issueInstantMaxAgeSeconds(): int
    {
        return IntegerSetting::read(
            $this->config,
            'sso.saml2.issue_instant_max_age_seconds',
            self::DEFAULT_ISSUE_INSTANT_MAX_AGE_SECONDS,
            self::MIN_ISSUE_INSTANT_MAX_AGE_SECONDS,
            self::MAX_ISSUE_INSTANT_MAX_AGE_SECONDS,
        );
    }
}
