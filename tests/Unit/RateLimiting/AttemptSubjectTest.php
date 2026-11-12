<?php

declare(strict_types = 1);

namespace Tests\Unit\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;

/**
 * Unit tests for an attempt at a rate-limited flow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptSubject::class)]
#[CoversClass(AttemptFlow::class)]
#[CoversClass(AttemptScope::class)]
final class AttemptSubjectTest extends TestCase
{
    /**
     * Each flow is counted in its scopes, under its key in `sso.rate_limits`.
     *
     * @return void
     */
    public function testEachFlowIsCountedInItsScopes(): void
    {
        $scopes = [];

        foreach (AttemptFlow::cases() as $flow) {
            $scopes[$flow->value] = array_column($flow->scopes(), 'value');
        }

        self::assertSame([
            'authorization_request' => ['per_ip', 'per_email_domain'],
            'completion'            => ['per_ip', 'per_connection'],
            'redemption'            => ['per_ip'],
            'metadata'              => ['per_connection'],
            'domain_check'          => ['per_connection'],
        ], $scopes);
    }

    /**
     * Each constructor names its flow and counts what it was given, by scope.
     *
     * @return void
     */
    public function testEachAttemptIsCountedAgainstWhatItNames(): void
    {
        $discovery = ['per_ip' => '203.0.113.7', 'per_email_domain' => 'example.com'];

        $cases = [
            [AttemptSubject::authorizationRequest(new ClientContext('203.0.113.7', null), 'example.com'), AttemptFlow::AUTHORIZATION_REQUEST, $discovery],
            [AttemptSubject::authorizationRequest(new ClientContext('203.0.113.7', null)), AttemptFlow::AUTHORIZATION_REQUEST, ['per_ip' => '203.0.113.7']],
            [AttemptSubject::completion(new ClientContext('203.0.113.7', null), 'conn_1'), AttemptFlow::COMPLETION, ['per_ip' => '203.0.113.7', 'per_connection' => 'conn_1']],
            [AttemptSubject::completion(new ClientContext(null, null), 'conn_1'), AttemptFlow::COMPLETION, ['per_connection' => 'conn_1']],
            [AttemptSubject::redemption(new ClientContext('203.0.113.7', null)), AttemptFlow::REDEMPTION, ['per_ip' => '203.0.113.7']],
            [AttemptSubject::redemption(new ClientContext(null, null)), AttemptFlow::REDEMPTION, []],
            [AttemptSubject::metadata('conn_1'), AttemptFlow::METADATA, ['per_connection' => 'conn_1']],
            [AttemptSubject::domainCheck('conn_1'), AttemptFlow::DOMAIN_CHECK, ['per_connection' => 'conn_1']],
        ];

        foreach ($cases as [$subject, $flow, $counted]) {
            self::assertSame($flow, $subject->flow);
            self::assertSame($counted, $subject->counted());
        }

        $subject = AttemptSubject::completion(new ClientContext('203.0.113.7', null), 'conn_1');

        self::assertSame(['203.0.113.7', null, 'conn_1'], [$subject->ip, $subject->emailDomain, $subject->connection]);
    }
}
