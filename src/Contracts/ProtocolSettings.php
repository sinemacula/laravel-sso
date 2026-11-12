<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The typed, immutable settings of one protocol, which the management helpers
 * validate, store and classify changes through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProtocolSettings
{
    /**
     * Never throw on bad input; keep it for `violations()` to report.
     *
     * @param  array<array-key, mixed>  $values
     * @return static
     */
    public static function fromArray(array $values): static;

    /**
     * Settings stored encrypted apart from the rest and masked on read.
     *
     * @return list<string>
     */
    public static function secretNames(): array;

    /**
     * Settings whose change may alter what existing subjects mean, refused on a
     * connection with links except through a migration.
     *
     * @return list<string>
     */
    public static function subjectNames(): array;

    /**
     * Settings that name the issuer the linking policy was stated about.
     *
     * @return list<string>
     */
    public static function issuerNames(): array;

    /**
     * The freshness a change to the setting needs, or `null` when the change
     * never widens or redirects access.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    public static function freshnessFor(string $name): ?FreshnessOperation;

    /**
     * The settings to store, with no secret.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array;

    /**
     * Every problem, in setting order, never echoing a value.
     *
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    public function violations(): array;

    /**
     * Whether every setting a flow needs is set, secrets and keys aside.
     *
     * @return bool
     */
    public function isComplete(): bool;
}
