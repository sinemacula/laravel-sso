<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

/**
 * Normalises a domain as the package stores and compares it (SSO-3.1): trimmed
 * of surrounding whitespace, without its trailing dot, converted to ASCII by
 * IDNA (UTS #46, non-transitional, with the STD3 rules and the bidirectional
 * and contextual checks) and in lower case, so `Bücher.Example.COM.` is
 * `xn--bcher-kva.example.com`.
 *
 * Only a host name that could be registered is accepted: at least two labels,
 * each 1 to 63 letters, digits and hyphens with no hyphen at either end, at
 * most 253 characters in all, under a top-level label of letters or an IDNA
 * one. An IP address, a wildcard, a label with an underscore or any other
 * character, a single label and a name under a special-use top-level domain
 * (`localhost`, `local`, `test`, `invalid`, `example`, `internal`, `arpa`,
 * `onion`, `alt`) normalise to nothing. Whether the name is a public suffix
 * (`co.uk`) is not judged: no tenant but its registry could publish the record
 * that verifies it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DomainName
{
    /** @var int The longest normalised domain, in characters. */
    public const int MAX_LENGTH = 253;

    /** @var int The longest domain given that is normalised at all, in bytes. */
    private const int MAX_INPUT_LENGTH = 1024;

    /** @var string A label of the normalised name. */
    private const string LABEL = '/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/';

    /** @var string A top-level label: letters, or an IDNA label. */
    private const string TOP_LEVEL_LABEL = '/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/';

    /** @var list<string> The special-use top-level domains no tenant can own (RFC 2606, 6761, 6762, 7686, 9476, and `internal`). */
    private const array SPECIAL_USE = ['localhost', 'local', 'test', 'invalid', 'example', 'internal', 'arpa', 'onion', 'alt'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The domain, normalised, or `null` when it is not a host name that could
     * be registered.
     *
     * @param  string  $given
     * @return ?string
     */
    public static function normalize(string $given): ?string
    {
        $value = trim($given);

        if ($value === '' || strlen($value) > self::MAX_INPUT_LENGTH) {
            return null;
        }

        $ascii = self::toAscii(str_ends_with($value, '.') ? substr($value, 0, -1) : $value);

        return $ascii !== null && self::isHostName($ascii) ? $ascii : null;
    }

    /**
     * Whether the normalised domain is the listed one or under it.
     *
     * @param  string  $domain
     * @param  list<string>  $listed
     * @return bool
     */
    public static function isListed(string $domain, array $listed): bool
    {
        foreach ($listed as $entry) {
            if ($domain === $entry || str_ends_with($domain, '.' . $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The value converted to lower-case ASCII by IDNA, or `null` when IDNA
     * refuses it.
     *
     * @param  string  $value
     * @return ?string
     */
    private static function toAscii(string $value): ?string
    {
        $flags = IDNA_NONTRANSITIONAL_TO_ASCII | IDNA_USE_STD3_RULES | IDNA_CHECK_BIDI | IDNA_CHECK_CONTEXTJ;
        $info  = [];
        $ascii = idn_to_ascii($value, $flags, INTL_IDNA_VARIANT_UTS46, $info);

        return is_string($ascii) && ($info['errors'] ?? 0) === 0 ? strtolower($ascii) : null;
    }

    /**
     * Whether the ASCII name is a host name that could be registered.
     *
     * @param  string  $ascii
     * @return bool
     */
    private static function isHostName(string $ascii): bool
    {
        $labels = explode('.', $ascii);
        $top    = end($labels);

        if (strlen($ascii) > self::MAX_LENGTH || count($labels) < 2 || in_array($top, self::SPECIAL_USE, true)) {
            return false;
        }

        return preg_match(self::TOP_LEVEL_LABEL, $top) === 1 && self::areLabels($labels);
    }

    /**
     * Whether each label is 1 to 63 letters, digits and hyphens, with no hyphen
     * at either end.
     *
     * @param  list<string>  $labels
     * @return bool
     */
    private static function areLabels(array $labels): bool
    {
        foreach ($labels as $label) {
            if (preg_match(self::LABEL, $label) !== 1) {
                return false;
            }
        }

        return true;
    }
}
