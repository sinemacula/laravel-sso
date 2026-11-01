<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Localization;

use Illuminate\Contracts\Translation\Translator;
use SineMacula\Laravel\Sso\Localization\Enums\Message;

/**
 * The messages the package can put in front of a consumer, translated through
 * Laravel's translator under the package's `sso` namespace (SSO-12.6).
 *
 * A message is read in the locale asked for, or the translator's current one,
 * and then in the application's fallback locale, as Laravel reads any line; a
 * line the application publishes to `lang/vendor/sso/{locale}/messages.php`
 * replaces the package's. When neither locale has a line, the message is read
 * again in English, the package's own fallback whatever the application's is. A
 * message without an English line is a bug in the package, and throws.
 *
 * The message is plain text: whoever renders it in HTML escapes it, since an
 * application's translation, and a replacement in particular, may hold
 * anything.
 *
 * It keeps only the translator it was given, and reads the locale on each call,
 * so nothing of one request or job outlives it (SSO-11.2).
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

    /** @var string The locale the package's own lines are written in, read when the locale asked for has no line. */
    private const string FALLBACK_LOCALE = 'en';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Translation\Translator  $translator
     */
    public function __construct(

        /** The application's translator */
        private Translator $translator,
    ) {}

    /**
     * Translate the message in the locale given, or the current locale, with
     * Laravel's `:placeholder` replacements, falling back to English when that
     * locale and the application's fallback have no line.
     *
     * The answer is plain text, for the caller to escape.
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
     * Whether the translator has a line for the key in the locale or the
     * application's fallback locale.
     *
     * The translator answers a key it has no line for with the key itself, so
     * the line is read without replacements: one could otherwise turn the key
     * into something else and pass for a line.
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
