<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Localization;

use Illuminate\Contracts\Translation\Translator;
use SineMacula\Laravel\Sso\Localization\Enums\Message;

/**
 * Translates the package's user-facing messages under the `sso` namespace.
 *
 * Falls back to English whatever the application's fallback locale is. The
 * result is plain text for the caller to escape.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Messages
{
    /** @var string The prefix of every message's key: the namespace and the translation file. */
    private const string KEY_PREFIX = 'sso::messages.';

    /** @var string The locale the package's own lines are written in. */
    private const string FALLBACK_LOCALE = 'en';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Translation\Translator  $translator
     */
    public function __construct(

        /** The application's translator. */
        private Translator $translator,
    ) {}

    /**
     * Translate the message in the given or current locale, else in English.
     *
     * @param  \SineMacula\Laravel\Sso\Localization\Enums\Message  $message
     * @param  array<string, int|string>  $replace
     * @param  string|null  $locale
     * @return string
     *
     * @throws \LogicException
     */
    public function get(Message $message, array $replace = [], ?string $locale = null): string
    {
        $key = self::KEY_PREFIX . $message->value;

        foreach ([$locale ?? $this->translator->getLocale(), self::FALLBACK_LOCALE] as $candidate) {
            if ($this->hasLine($key, $candidate)) {
                return (string) $this->translator->get($key, $replace, $candidate);
            }
        }

        throw new \LogicException(sprintf('The package has no English line for the message %s.', $key));
    }

    /**
     * Whether the locale, or the application's fallback, has a line for the
     * key.
     *
     * Read without replacements, since a replacement could alter the echoed key
     * and pass for a line.
     *
     * @param  string  $key
     * @param  string  $locale
     * @return bool
     */
    private function hasLine(string $key, string $locale): bool
    {
        $line = $this->translator->get($key, [], $locale);

        return is_string($line) && $line !== $key;
    }
}
