<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Sessions;

use SineMacula\Laravel\Sso\Evidence\EvidenceRules;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * The value domains of a session provenance's parts, which bound its stored
 * JSON to `Provenance::MAX_STORED_JSON_BYTES`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ProvenanceDomain
{
    /** @var string One or more printable ASCII characters. */
    private const string PRINTABLE = '/^[\x20-\x7E]+$/D';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse a value that is not 1 to `$maxBytes` of printable ASCII.
     *
     * @param  string  $name
     * @param  ?string  $value
     * @param  int  $maxBytes
     * @param  bool  $optional
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertText(string $name, #[\SensitiveParameter] ?string $value, int $maxBytes, bool $optional): void
    {
        $valid = $value === null ? $optional : self::isPrintable($value, $maxBytes);

        if ($valid) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('A session provenance\'s %s is 1 to %d bytes of printable ASCII%s.', $name, $maxBytes, $optional ? ' or null' : ''));
    }

    /**
     * Refuse a tenant id that is empty, too long or not valid UTF-8.
     *
     * @param  string  $tenantId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertTenant(string $tenantId): void
    {
        if ($tenantId === '' || strlen($tenantId) > Provenance::MAX_ID_LENGTH || !mb_check_encoding($tenantId, 'UTF-8')) {
            throw new \InvalidArgumentException(sprintf('A session provenance\'s tenant id is 1 to %d bytes of UTF-8.', Provenance::MAX_ID_LENGTH));
        }
    }

    /**
     * Refuse a protocol that is not a registered driver's name.
     *
     * @param  string  $protocol
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertProtocol(string $protocol): void
    {
        if (preg_match(ProtocolManager::NAME_PATTERN, $protocol) !== 1) {
            throw new \InvalidArgumentException('A session provenance\'s protocol is a driver\'s name: a lower-case letter, then up to 63 of them, digits or underscores.');
        }
    }

    /**
     * Refuse anything but a list of distinct RFC 8176 registered methods.
     *
     * @param  array<array-key, mixed>  $methods
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertMethods(#[\SensitiveParameter] array $methods): void
    {
        if (!array_is_list($methods) || self::registered($methods) !== $methods) {
            throw new \InvalidArgumentException('A session provenance keeps a list of RFC 8176\'s registered methods, each at most once.');
        }
    }

    /**
     * The distinct RFC 8176 registered methods among those given, in order.
     *
     * @param  array<array-key, mixed>  $methods
     * @return list<string>
     */
    public static function registered(#[\SensitiveParameter] array $methods): array
    {
        $registered = array_filter($methods, static fn (mixed $method): bool => in_array($method, EvidenceRules::RFC_8176_METHODS, true));

        return array_values(array_unique($registered));
    }

    /**
     * The raw context class if within its domain, else `null`.
     *
     * @param  ?string  $raw
     * @return ?string
     */
    public static function keptContext(#[\SensitiveParameter] ?string $raw): ?string
    {
        return $raw !== null && self::isPrintable($raw, Provenance::MAX_CONTEXT_LENGTH) ? $raw : null;
    }

    /**
     * Whether the value is 1 to the bytes allowed of printable ASCII.
     *
     * @param  string  $value
     * @param  int  $maxBytes
     * @return bool
     */
    private static function isPrintable(#[\SensitiveParameter] string $value, int $maxBytes): bool
    {
        return strlen($value) <= $maxBytes && preg_match(self::PRINTABLE, $value) === 1;
    }
}
