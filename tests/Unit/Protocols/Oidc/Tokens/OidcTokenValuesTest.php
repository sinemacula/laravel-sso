<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Tokens;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for the values a completion's provider tokens are held in (SSO-7.2
 * to SSO-7.6): each gives its tokens and claims only through its accessors,
 * shows none of them in any dump or in JSON, and refuses to be serialised or
 * unserialised; a validated ID token carries its own issuer and a non-empty
 * subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenResponse::class)]
#[CoversClass(ValidatedIdToken::class)]
#[CoversClass(IdTokenValidation::class)]
final class OidcTokenValuesTest extends TestCase
{
    use DumpsValues;

    /**
     * A token response gives its tokens through its accessors alone.
     *
     * @return void
     */
    public function testATokenResponseHidesItsTokens(): void
    {
        $tokens = new TokenResponse('id.token.secret-id', 'secret-access', 'bearer');

        self::assertSame(['id.token.secret-id', 'secret-access', 'bearer'], [$tokens->idToken(), $tokens->accessToken(), $tokens->tokenType]);
        self::assertSame('Bearer', (new TokenResponse('a.b.c', 'd'))->tokenType);
        self::assertSame(['id_token' => '[redacted]', 'access_token' => '[redacted]', 'token_type' => 'bearer'], $tokens->__debugInfo());
        self::assertSame('{"id_token":"[redacted]","access_token":"[redacted]","token_type":"bearer"}', json_encode($tokens));

        foreach (self::dumps($tokens) as $dumper => $dump) {
            self::assertStringNotContainsString('secret', $dump, $dumper);
        }

        self::assertNeverSerialized($tokens, 'A token response cannot be serialised.', 'A token response cannot be unserialised.');
    }

    /**
     * A validated ID token gives its subject and claims through its accessors
     * alone.
     *
     * @return void
     */
    public function testAValidatedIdTokenHidesItsClaims(): void
    {
        $claims = ['iss' => 'https://op.example.test', 'sub' => 'secret-subject', 'email' => 'secret@example.test'];
        $token  = new ValidatedIdToken('https://op.example.test', 'secret-subject', $claims);

        self::assertSame(['https://op.example.test', 'secret-subject'], [$token->issuer, $token->subject()]);
        self::assertSame(['secret@example.test', null], [$token->claim('email'), $token->claim('name')]);
        self::assertSame(['iss', 'sub', 'email'], array_keys($token->claims()));
        self::assertSame(['issuer' => 'https://op.example.test', 'claims' => ['iss', 'sub', 'email']], $token->__debugInfo());
        self::assertSame('{"issuer":"https:\/\/op.example.test","claims":["iss","sub","email"]}', json_encode($token));

        foreach (self::dumps($token) as $dumper => $dump) {
            self::assertStringNotContainsString('secret', $dump, $dumper);
        }

        self::assertNeverSerialized($token, 'A validated ID token cannot be serialised.', 'A validated ID token cannot be unserialised.');
    }

    /**
     * A validated ID token whose subject is empty or not its own, or whose
     * issuer is not its own, is the validator's mistake.
     *
     * @return void
     */
    public function testAValidatedIdTokenCarriesItsOwnIssuerAndSubject(): void
    {
        $cases = [
            ['https://op.example.test', '', ['iss' => 'https://op.example.test', 'sub' => '']],
            ['https://op.example.test', 'a', ['iss' => 'https://op.example.test', 'sub' => 'b']],
            ['https://op.example.test', 'a', ['iss' => 'https://other.example.test', 'sub' => 'a']],
            ['https://op.example.test', 'a', ['sub' => 'a']],
        ];

        foreach ($cases as [$issuer, $subject, $claims]) {
            try {
                new ValidatedIdToken($issuer, $subject, $claims);
                self::fail('A token without its own issuer and subject was built.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A validated ID token carries its own issuer and a non-empty subject.', $exception->getMessage());
            }
        }
    }

    /**
     * A validation is validated with its token, or refused with its reason.
     *
     * @return void
     */
    public function testAValidationIsOneOrTheOther(): void
    {
        $token     = new ValidatedIdToken('https://op.example.test', 'a', ['iss' => 'https://op.example.test', 'sub' => 'a']);
        $validated = IdTokenValidation::validated($token);
        $refused   = IdTokenValidation::refused(FailureReason::NONCE_MISMATCH);

        self::assertSame([true, $token, null], [$validated->isValidated(), $validated->token, $validated->reason]);
        self::assertSame([false, null, FailureReason::NONCE_MISMATCH], [$refused->isValidated(), $refused->token, $refused->reason]);
    }

    /**
     * Assert the value refuses to be serialised and unserialised, with the
     * messages given.
     *
     * @param  object  $value
     * @param  string  $serialise
     * @param  string  $unserialise
     * @return void
     */
    private static function assertNeverSerialized(object $value, string $serialise, string $unserialise): void
    {
        $restore = static fn (): mixed => unserialize('O:' . strlen($value::class) . ':"' . $value::class . '":0:{}');

        self::assertSame([$serialise, $unserialise], [self::refusal(static fn (): string => serialize($value)), self::refusal($restore)]);
    }

    /**
     * The message of the `LogicException` the work throws, or none.
     *
     * @param  \Closure(): mixed  $work
     * @return ?string
     */
    private static function refusal(\Closure $work): ?string
    {
        try {
            $work();
        } catch (\LogicException $exception) {
            return $exception->getMessage();
        }

        return null;
    }
}
