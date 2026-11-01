<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The package's logging settings under `sso.logging`: the channel it logs to,
 * how much of an identity provider's diagnostic text it keeps, and the key
 * names whose values are redacted (SSO-5.7, SSO-9.8, SSO-11.9).
 *
 * Every value is read on each call, so nothing is kept across requests
 * (SSO-11.2). A malformed value fails closed with an `InvalidArgumentException`
 * naming its key, never a value that would widen what is logged: the redacted
 * keys are always the built-in ones (`Redactor::REDACTED_KEYS`) plus those
 * configured, and a configured list can add a key but never remove one.
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
     * The key in the form every redacted key is compared in: lower case, with
     * everything but `a` to `z` and `0` to `9` removed, so `Client-Secret`,
     * `CLIENT_SECRET` and `clientSecret` are the same key.
     *
     * @param  string  $key
     * @return string
     */
    public static function normalizeKey(string $key): string
    {
        return (string) preg_replace('/[^a-z0-9]/', '', strtolower($key));
    }

    /**
     * The channel the package logs to, or `null` for Laravel's default channel.
     * An empty string is the default channel too, as an unset
     * `SSO_LOG_CHANNEL=` gives one. Whether the channel is configured is
     * `assertChannelConfigured()`'s answer.
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
     * Fail unless the channel is the default one or a channel
     * `logging.channels` configures. The message names the channel, which is a
     * name, never a secret.
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
     * The most characters of an identity provider's diagnostic text kept, from
     * 64 to 4096 (512 by default).
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
     * Every redacted key, normalised: the built-in ones, then those configured
     * in `sso.logging.redacted_keys`, each once. The configured value must be a
     * list of strings, each holding a letter or a digit, so none normalises to
     * an empty key.
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
     * Fail on the first setting that is malformed: the channel, which must also
     * be configured, the diagnostic length and the redacted keys.
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
     * The exception a malformed list of redacted keys fails with.
     *
     * @return \InvalidArgumentException
     */
    private static function malformedRedactedKeys(): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('`%s` must be a list of key names, each holding a letter or a digit.', self::REDACTED_KEYS));
    }
}
