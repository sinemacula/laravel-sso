<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The typed settings of one protocol (SSO-2.3, SSO-2.4): what a driver reads a
 * connection's stored settings as, and what the management helpers validate,
 * store, compare and classify a change to through it.
 *
 * Built from what was given or stored with `fromArray()`, which never throws on
 * bad input: `violations()` reports every problem, each naming the setting and
 * a code, never echoing a value. `toArray()` is what is stored, and holds no
 * secret: a secret setting (a client secret) is named by `secretNames()`, taken
 * out of what was given before `fromArray()` sees it, and stored encrypted
 * apart from the settings (SSO-2.5).
 *
 * The classification is the driver's, and the helpers act on it alone:
 * `freshnessFor()` names the operation whose freshness a change to a setting
 * needs (SSO-2.12), `subjectNames()` the settings a change to which may alter
 * what existing subjects mean (SSO-2.13), and `issuerNames()` the settings that
 * name the issuer an administrator's linking policy was stated about (SSO-8.8).
 * A setting with no operation is profile or presentation, which never widens
 * access.
 *
 * An implementation is an immutable value and holds nothing of one request for
 * the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProtocolSettings
{
    /**
     * The settings the values give, by name, whatever their shape: a value of
     * the wrong type or format is kept for `violations()` to report, never
     * thrown.
     *
     * @param  array<array-key, mixed>  $values
     * @return static
     */
    public static function fromArray(array $values): static;

    /**
     * The names of the settings that are secrets, stored encrypted and masked
     * on read.
     *
     * @return list<string>
     */
    public static function secretNames(): array;

    /**
     * The names of the settings a change to which may alter what existing
     * subjects mean (the issuer or entity id, the client id, the subject
     * source, the NameID format), refused on a connection with links except
     * through a migration helper (SSO-2.13).
     *
     * @return list<string>
     */
    public static function subjectNames(): array;

    /**
     * The names of the settings that name the issuer, a change to which leaves
     * the connection's linking policy stated about another issuer (SSO-8.8).
     *
     * @return list<string>
     */
    public static function issuerNames(): array;

    /**
     * The operation whose freshness a change to the setting needs, or `null`
     * for a setting whose change never widens or redirects access.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    public static function freshnessFor(string $name): ?FreshnessOperation;

    /**
     * The settings to store, by name, with no secret.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array;

    /**
     * Every problem with the settings, in the order the settings are named;
     * none for valid settings.
     *
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    public function violations(): array;

    /**
     * Whether every setting a flow needs is set (secrets and keys aside, which
     * the driver judges with the connection).
     *
     * @return bool
     */
    public function isComplete(): bool;
}
