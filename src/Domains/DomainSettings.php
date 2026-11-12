<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The `sso.domains` settings, read on each call and failing closed when
 * malformed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainSettings
{
    /** @var string The record name when none is configured. */
    public const string DEFAULT_RECORD_NAME = '_sso-verification';

    /** @var int The longest record name, in characters. */
    public const int MAX_RECORD_NAME_LENGTH = 63;

    /** @var int A claim's lifetime when none is configured, in seconds (a week). */
    public const int DEFAULT_PENDING_EXPIRY_SECONDS = 604800;

    /** @var int The grace period when none is configured, in seconds (three days). */
    public const int DEFAULT_RECHECK_GRACE_SECONDS = 259200;

    /** @var int The default and ceiling linking maximum age, in seconds (a day). */
    public const int MAX_LINKING_AGE_SECONDS = 86400;

    /** @var list<string> Public mailbox providers, always refused whatever is configured. */
    public const array PUBLIC_MAILBOX_PROVIDERS = [
        '126.com', '163.com', 'aol.com', 'fastmail.com', 'gmail.com', 'gmx.com', 'gmx.de', 'gmx.net', 'googlemail.com',
        'hey.com', 'hotmail.co.uk', 'hotmail.com', 'icloud.com', 'live.com', 'mac.com', 'mail.com', 'mail.ru', 'me.com',
        'msn.com', 'naver.com', 'outlook.com', 'pm.me', 'proton.me', 'protonmail.com', 'qq.com', 'rocketmail.com',
        'tuta.io', 'tutanota.com', 'web.de', 'yahoo.co.uk', 'yahoo.com', 'yandex.com', 'yandex.ru', 'ymail.com',
        'zoho.com',
    ];

    /** @var int The longest a claim may wait or a grace period last, in seconds (30 days). */
    private const int MAX_PERIOD_SECONDS = 2592000;

    /** @var string One to four labels of `[a-z0-9_-]`, no `-` at either end. */
    private const string RECORD_NAME = '/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?){0,3}$/';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private Repository $config,
    ) {}

    /**
     * The name the TXT record is looked up at under a domain.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function recordName(): string
    {
        $name = $this->config->get('sso.domains.record_name', self::DEFAULT_RECORD_NAME);

        if (!self::isRecordName($name)) {
            $message = 'sso.domains.record_name must be one to four labels of lower-case letters, digits, `-` and `_`, at most %d characters.';

            throw new \InvalidArgumentException(sprintf($message, self::MAX_RECORD_NAME_LENGTH));
        }

        return $name;
    }

    /**
     * The public mailbox providers, then those configured, normalised and
     * listed once.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function refused(): array
    {
        $configured = $this->config->get('sso.domains.refused', []);

        if (!is_array($configured) || !array_is_list($configured)) {
            throw new \InvalidArgumentException('sso.domains.refused must be a list of domains.');
        }

        $refused = self::PUBLIC_MAILBOX_PROVIDERS;

        foreach ($configured as $index => $domain) {

            $normalized = is_string($domain) ? DomainName::normalize($domain) : null;

            if ($normalized === null) {
                throw new \InvalidArgumentException(sprintf('sso.domains.refused.%d must be a domain name.', $index));
            }

            $refused[] = $normalized;
        }

        return array_values(array_unique($refused));
    }

    /**
     * How long a claim waits to be verified, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function pendingExpirySeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.domains.pending_expiry_seconds', self::DEFAULT_PENDING_EXPIRY_SECONDS, 3600, self::MAX_PERIOD_SECONDS);
    }

    /**
     * How long a verified domain whose record has gone keeps routing discovery
     * before it lapses, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function recheckGraceSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.domains.recheck_grace_seconds', self::DEFAULT_RECHECK_GRACE_SECONDS, 0, self::MAX_PERIOD_SECONDS);
    }

    /**
     * How recent the last successful check must be for the domain to allow
     * linking by email, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function linkingMaxAgeSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.domains.linking_max_age_seconds', self::MAX_LINKING_AGE_SECONDS, 60, self::MAX_LINKING_AGE_SECONDS);
    }

    /**
     * Whether the value is a valid record name.
     *
     * @param  mixed  $name
     * @return bool
     *
     * @phpstan-assert-if-true string $name
     */
    private static function isRecordName(mixed $name): bool
    {
        if (!is_string($name) || strlen($name) > self::MAX_RECORD_NAME_LENGTH) {
            return false;
        }

        return preg_match(self::RECORD_NAME, $name) === 1;
    }
}
