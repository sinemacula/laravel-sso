<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\IdTokens;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\AudienceRules;

/**
 * Unit tests for who an ID token is for (SSO-7.4): the client id exactly among
 * `aud`, every other audience trusted, `azp` required with several audiences
 * and the client id when present, and each way round those rules refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AudienceRules::class)]
final class AudienceRulesTest extends TestCase
{
    /** @var string The connection's client id. */
    private const string CLIENT = 'client';

    /** @var string An audience the connection trusts. */
    private const string TRUSTED = 'https://api.example.test';

    /** @var string An audience the connection does not trust. */
    private const string UNTRUSTED = 'https://other.example.test';

    /**
     * Rows of `[claims]`: an audience and authorised party that pass.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideAdmittedClaims(): iterable
    {
        yield from [
            'the client as a string'         => [['aud' => self::CLIENT]],
            'the client as a list'           => [['aud' => [self::CLIENT]]],
            'the client, with azp'           => [['aud' => self::CLIENT, 'azp' => self::CLIENT]],
            'the client in a list, with azp' => [['aud' => [self::CLIENT], 'azp' => self::CLIENT]],
            'the client and a trusted one'   => [['aud' => [self::CLIENT, self::TRUSTED], 'azp' => self::CLIENT]],
            'a trusted one and the client'   => [['aud' => [self::TRUSTED, self::CLIENT], 'azp' => self::CLIENT]],
            'the client and two trusted'     => [['aud' => [self::CLIENT, self::TRUSTED, 'second-trusted'], 'azp' => self::CLIENT]],
        ];
    }

    /**
     * An audience that holds the client, with every other trusted, passes.
     *
     * @param  array<string, mixed>  $claims
     * @return void
     */
    #[DataProvider('provideAdmittedClaims')]
    public function testAnAdmittedAudiencePasses(array $claims): void
    {
        self::assertNull(AudienceRules::refusal($claims, self::CLIENT, [self::TRUSTED, 'second-trusted']));
    }

    /**
     * Rows of `[claims]`: each way round the rules.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideRefusedClaims(): iterable
    {
        yield from [
            'the client and an untrusted one'       => [['aud' => [self::CLIENT, self::UNTRUSTED], 'azp' => self::CLIENT]],
            'an untrusted one, trusted one, client' => [['aud' => [self::UNTRUSTED, self::TRUSTED, self::CLIENT], 'azp' => self::CLIENT]],
            'the client and a trusted, no azp'      => [['aud' => [self::CLIENT, self::TRUSTED]]],
            'azp another client'                    => [['aud' => self::CLIENT, 'azp' => 'another-client']],
            'azp a trusted audience'                => [['aud' => [self::CLIENT, self::TRUSTED], 'azp' => self::TRUSTED]],
            'azp of another case'                   => [['aud' => self::CLIENT, 'azp' => 'CLIENT']],
            'azp with whitespace'                   => [['aud' => self::CLIENT, 'azp' => ' client']],
            'azp empty'                             => [['aud' => self::CLIENT, 'azp' => '']],
            'azp null'                              => [['aud' => self::CLIENT, 'azp' => null]],
            'the client of another case'            => [['aud' => 'CLIENT']],
            'the client with a trailing space'      => [['aud' => 'client ']],
            'the client with a leading space'       => [['aud' => ' client']],
            'the client of another case, listed'    => [['aud' => ['Client']]],
            'only a trusted audience'               => [['aud' => self::TRUSTED]],
            'only a trusted audience, listed'       => [['aud' => [self::TRUSTED]]],
            'only a trusted audience, with azp'     => [['aud' => [self::TRUSTED], 'azp' => self::CLIENT]],
            'only trusted audiences'                => [['aud' => [self::TRUSTED, 'second-trusted'], 'azp' => self::CLIENT]],
            'only an untrusted audience'            => [['aud' => self::UNTRUSTED, 'azp' => self::CLIENT]],
            'a trusted audience of another case'    => [['aud' => [self::CLIENT, 'HTTPS://API.EXAMPLE.TEST'], 'azp' => self::CLIENT]],
            'no audience'                           => [[]],
        ];
    }

    /**
     * Each way round the rules is `audience_mismatch`.
     *
     * @param  array<string, mixed>  $claims
     * @return void
     */
    #[DataProvider('provideRefusedClaims')]
    public function testARefusedAudienceIsAMismatch(array $claims): void
    {
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, AudienceRules::refusal($claims, self::CLIENT, [self::TRUSTED, 'second-trusted']));
    }

    /**
     * With nothing trusted, another audience is always refused, and the client
     * alone passes.
     *
     * @return void
     */
    public function testNothingIsTrustedByDefault(): void
    {
        self::assertNull(AudienceRules::refusal(['aud' => self::CLIENT], self::CLIENT, []));
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, AudienceRules::refusal(['aud' => [self::CLIENT, self::TRUSTED], 'azp' => self::CLIENT], self::CLIENT, []));
    }

    /**
     * Values that read as the same number are not the same audience, for the
     * client and for a trusted audience alike.
     *
     * @return void
     */
    public function testAudiencesAreNeverComparedAsNumbers(): void
    {
        self::assertNull(AudienceRules::refusal(['aud' => '1'], '1', []));
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, AudienceRules::refusal(['aud' => '01'], '1', []));
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, AudienceRules::refusal(['aud' => '1.0'], '1', []));
        self::assertNull(AudienceRules::refusal(['aud' => ['1', '02'], 'azp' => '1'], '1', ['02']));
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, AudienceRules::refusal(['aud' => ['1', '2'], 'azp' => '1'], '1', ['02']));
    }

    /**
     * Two calls in a row each see their own client and trusted audiences.
     *
     * @return void
     */
    public function testCallsInARowEachSeeTheirOwnConnection(): void
    {
        $claims = ['aud' => ['client-a', 'api-a'], 'azp' => 'client-a'];

        self::assertNull(AudienceRules::refusal($claims, 'client-a', ['api-a']));
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, AudienceRules::refusal($claims, 'client-b', ['api-b']));
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, AudienceRules::refusal($claims, 'client-a', ['api-b']));
        self::assertNull(AudienceRules::refusal($claims, 'client-a', ['api-a']));
    }
}
