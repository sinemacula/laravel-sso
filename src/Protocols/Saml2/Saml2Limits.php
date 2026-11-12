<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The SAML size caps and `IssueInstant` window from `sso.saml2`, read on each
 * call; a malformed value throws naming its key.
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
