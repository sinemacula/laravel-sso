<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\Migrations\Migration;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * Creates and drops the links, authorisation requests and handoff codes tables
 * through their shipped migrations, on the storage connection and under their
 * configured names, and makes rows for a test to work on. A test that uses it
 * uses `UsesConnections` too, since each row belongs to a connection.
 *
 * A test calls `createFlowTables()` in its `setUp()` and `dropFlowTables()` in
 * its `tearDown()`, before the parent's, so a persistent database starts the
 * next test without them. Each row is written through its model, so its key and
 * stamps come from the package's clock; what the attributes given name replaces
 * the defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesFlowTables
{
    /** @var list<string> The shipped migrations of the three tables, in the order they run. */
    private static array $flowMigrations = [
        '2026_11_03_000000_create_sso_links_table.php',
        '2026_11_03_000001_create_sso_authorization_requests_table.php',
        '2026_11_03_000002_create_sso_handoff_codes_table.php',
    ];

    /**
     * Run the three tables' shipped migrations.
     *
     * @return void
     */
    protected function createFlowTables(): void
    {
        foreach (self::$flowMigrations as $migration) {
            self::flowMigration($migration)->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Roll the three tables' shipped migrations back.
     *
     * @return void
     */
    protected function dropFlowTables(): void
    {
        foreach (array_reverse(self::$flowMigrations) as $migration) {
            self::flowMigration($migration)->down(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Make and save an authorisation request through the connection: a
     * `sign_in` for `web`, with a random reference and state digest, a fixed
     * challenge, expiring ten minutes after the clock's now, unless the
     * attributes given say otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    protected function makeAuthorizationRequest(Connection $connection, array $attributes = []): AuthorizationRequest
    {
        $request = new AuthorizationRequest;

        $request->forceFill($attributes + [
            'reference'         => rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '='),
            'state_digest'      => hash('sha256', random_bytes(24)),
            'purpose'           => 'sign_in',
            'application'       => 'web',
            'connection_id'     => $connection->id,
            'handoff_challenge' => str_repeat('c', 43),
            'expires_at'        => self::flowNow()->addMinutes(10),
        ])->save();

        return $request;
    }

    /**
     * Make and save a handoff code for the connection: a `sign_in` code for
     * `web`, with a random digest, a fixed reference and challenge, an empty
     * stored result, expiring a minute after the clock's now, unless the
     * attributes given say otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\HandoffCode
     */
    protected function makeHandoffCode(Connection $connection, array $attributes = []): HandoffCode
    {
        $code = new HandoffCode;

        $code->forceFill($attributes + [
            'code_digest'       => hash('sha256', random_bytes(32)),
            'purpose'           => 'sign_in',
            'application'       => 'web',
            'connection_id'     => $connection->id,
            'request_reference' => str_repeat('r', 32),
            'handoff_challenge' => str_repeat('c', 43),
            'result'            => '',
            'expires_at'        => self::flowNow()->addMinute(),
        ])->save();

        return $code;
    }

    /**
     * Make and save an active link through the connection: issuer
     * `https://idp.example.com`, the subject given, no NameID format, to `user`
     * `1`, unless the attributes given say otherwise. Its key is the one
     * `LinkSubject` derives from the issuer, format and subject the row ends up
     * with, so the link resolves through the store, unless a `subject_key` is
     * given.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $subject
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    protected function makeLink(Connection $connection, string $subject = 'subject-1', array $attributes = []): Link
    {
        $link = new Link;

        $attributes += [
            'connection_id' => $connection->id,
            'issuer'        => 'https://idp.example.com',
            'subject'       => $subject,
            'identity_type' => 'user',
            'identity_id'   => '1',
        ];

        $link->forceFill($attributes + ['subject_key' => self::flowSubjectKey($attributes)])->save();

        return $link;
    }

    /**
     * The key `LinkSubject` derives from the issuer, NameID format and subject
     * of the link's attributes.
     *
     * @param  array<string, mixed>  $attributes
     * @return string
     */
    private static function flowSubjectKey(array $attributes): string
    {
        $issuer  = $attributes['issuer'];
        $subject = $attributes['subject'];
        $format  = $attributes['name_id_format'] ?? null;

        assert(is_string($issuer) && is_string($subject));
        assert($format === null || is_string($format));

        return (new LinkSubject($issuer, $subject, $format))->key();
    }

    /**
     * The package's clock's now.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function flowNow(): CarbonImmutable
    {
        return Container::getInstance()->make(Clock::class)->now();
    }

    /**
     * The shipped migration of the name.
     *
     * @param  string  $name
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function flowMigration(string $name): Migration
    {
        return require dirname(__DIR__, 2) . '/database/migrations/' . $name;
    }
}
