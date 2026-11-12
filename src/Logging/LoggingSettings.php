<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The `sso.logging` settings, read on each call; a malformed value fails
 * closed, and configured redacted keys can only add to the built-in ones.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LoggingSettings
{
    /** @var int The diagnostic length kept when none is configured, in characters. */
    public const int DEFAULT_MAX_DIAGNOSTIC_LENGTH = 512;

    /** @var int The least diagnostic length that may be configured, in characters. */
    public const int MIN_DIAGNOSTIC_LENGTH = 64;

    /** @var int The greatest diagnostic length that may be configured, in characters. */
    public const int MAX_DIAGNOSTIC_LENGTH = 4096;

    /** @var string The key the channel is configured under. */
    private const string CHANNEL = 'sso.logging.channel';

    /** @var string The key the diagnostic length is configured under. */
    private const string MAX_LENGTH = 'sso.logging.max_diagnostic_length';

    /** @var string The key the added redacted keys are configured under. */
    private const string REDACTED_KEYS = 'sso.logging.redacted_keys';

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
     * Lower-case alphanumerics, so `Client-Secret` and `clientSecret` match.
     *
     * @param  string  $key
     * @return string
     */
    public static function normalizeKey(string $key): string
    {
        return (string) preg_replace('/[^a-z0-9]/', '', strtolower($key));
    }

    /**
     * The channel, `null` for the default; empty counts as unset, as
     * `SSO_LOG_CHANNEL=` gives.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function channel(): ?string
    {
        $channel = $this->config->get(self::CHANNEL);

        if ($channel !== null && !is_string($channel)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be the name of a channel in `logging.channels`, or null or empty for the default channel.', self::CHANNEL));
        }

        return $channel === '' ? null : $channel;
    }

    /**
     * Fail unless the channel is the default or in `logging.channels`.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function assertChannelConfigured(): void
    {
        $channel  = $this->channel();
        $channels = $this->config->get('logging.channels');

        if ($channel !== null && (!is_array($channels) || !is_array($channels[$channel] ?? null))) {
            throw new \InvalidArgumentException(sprintf('`%s` names the channel [%s], which is not configured in `logging.channels`.', self::CHANNEL, $channel));
        }
    }

    /**
     * The most characters of an identity provider's diagnostic text kept.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxDiagnosticLength(): int
    {
        return IntegerSetting::read($this->config, self::MAX_LENGTH, self::DEFAULT_MAX_DIAGNOSTIC_LENGTH, self::MIN_DIAGNOSTIC_LENGTH, self::MAX_DIAGNOSTIC_LENGTH);
    }

    /**
     * The built-in then configured redacted keys, normalised and deduplicated;
     * a configured key that normalises to empty is refused.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function redactedKeys(): array
    {
        $configured = $this->config->get(self::REDACTED_KEYS, []);

        if (!is_array($configured) || !array_is_list($configured)) {
            throw self::malformedRedactedKeys();
        }

        $keys = array_map(self::normalizeKey(...), Redactor::REDACTED_KEYS);

        foreach ($configured as $key) {

            $normalized = is_string($key) ? self::normalizeKey($key) : '';

            if ($normalized === '') {
                throw self::malformedRedactedKeys();
            }

            $keys[] = $normalized;
        }

        return array_values(array_unique($keys));
    }

    /**
     * Fail on the first malformed setting.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->assertChannelConfigured();
        $this->maxDiagnosticLength();
        $this->redactedKeys();
    }

    /**
     * The exception for a malformed list of redacted keys.
     *
     * @return \InvalidArgumentException
     */
    private static function malformedRedactedKeys(): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('`%s` must be a list of key names, each holding a letter or a digit.', self::REDACTED_KEYS));
    }
}
