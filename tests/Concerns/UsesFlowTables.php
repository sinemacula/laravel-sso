<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;

/**
 * Makes links, authorisation requests and handoff codes for a test to work on.
 * A test that uses it calls `usePackageTables()` in its `setUp()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesFlowTables
{
    /**
     * Make and save a `sign_in` request for `web` at the stored trust version,
     * unless overridden.
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
            'trust_version'     => (int) Connection::query()->whereKey($connection->id)->value('trust_version'),
            'expires_at'        => self::flowNow()->addMinutes(10),
        ])->save();

        return $request;
    }

    /**
     * Make and save a `sign_in` code for `web` at the model's trust version,
     * unless overridden.
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
            'trust_version'     => $connection->trust_version,
            'expires_at'        => self::flowNow()->addMinute(),
        ])->save();

        return $code;
    }

    /**
     * Make and save an active link to `user` `1`, unless overridden; its
     * subject key is derived from the final attributes, so it resolves.
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
     * The key `LinkSubject` derives from the link's attributes.
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
}
