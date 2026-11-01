<?php

declare(strict_types = 1);

namespace Tests\Unit\Fetching;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for an outbound credential: one per kind, each refusing an empty
 * part, and a secret that a dump, `json_encode()` and serialisation never show.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FetchCredentials::class)]
#[CoversClass(CredentialKind::class)]
final class FetchCredentialsTest extends TestCase
{
    /** @var string A secret no output may show. */
    private const string SECRET = 'the-secret-value';

    /**
     * Each named constructor gives its kind, the client id where it has one,
     * and the secret to the fetcher.
     *
     * @return void
     */
    public function testEachKindHoldsItsParts(): void
    {
        $basic     = FetchCredentials::clientSecretBasic('client', self::SECRET);
        $post      = FetchCredentials::clientSecretPost('client', self::SECRET);
        $assertion = FetchCredentials::privateKeyJwt('client', self::SECRET);
        $token     = FetchCredentials::accessToken(self::SECRET);

        self::assertSame(
            [CredentialKind::CLIENT_SECRET_BASIC, CredentialKind::CLIENT_SECRET_POST, CredentialKind::PRIVATE_KEY_JWT, CredentialKind::ACCESS_TOKEN],
            [$basic->kind, $post->kind, $assertion->kind, $token->kind],
        );
        self::assertSame(['client', 'client', 'client', null], [$basic->clientId, $post->clientId, $assertion->clientId, $token->clientId]);
        self::assertSame([self::SECRET], array_values(array_unique([$basic->secret(), $post->secret(), $assertion->secret(), $token->secret()])));

        self::assertTrue($basic->kind->isClientAuthentication());
        self::assertTrue($post->kind->isClientAuthentication());
        self::assertTrue($assertion->kind->isClientAuthentication());
        self::assertFalse($token->kind->isClientAuthentication());
    }

    /**
     * An empty client id or secret is a caller's mistake.
     *
     * @return void
     */
    public function testRefusesAnEmptyPart(): void
    {
        $attempts = [
            static fn (): FetchCredentials => FetchCredentials::clientSecretBasic('', self::SECRET),
            static fn (): FetchCredentials => FetchCredentials::clientSecretPost('client', ''),
            static fn (): FetchCredentials => FetchCredentials::privateKeyJwt('', self::SECRET),
            static fn (): FetchCredentials => FetchCredentials::accessToken(''),
        ];

        foreach ($attempts as $attempt) {
            try {
                $attempt();

                self::fail('Expected the credential to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertNotSame('', $exception->getMessage());
            }
        }
    }

    /**
     * Neither a dump, `print_r()` nor `json_encode()` shows the secret.
     *
     * @return void
     */
    public function testTheSecretNeverLeaves(): void
    {
        $credentials = FetchCredentials::clientSecretPost('client', self::SECRET);

        self::assertSame(['kind' => 'client_secret_post', 'clientId' => 'client', 'secret' => '[redacted]'], $credentials->__debugInfo());
        self::assertStringNotContainsString(self::SECRET, print_r($credentials, true));
        self::assertStringNotContainsString(self::SECRET, (string) json_encode($credentials));
    }

    /**
     * The secret of every kind is held where no dump, export or array cast can
     * reach it: Laravel's `dump()` lists private properties beside
     * `__debugInfo()`, so masking the dump alone is not enough.
     *
     * @return void
     */
    public function testNoDumpExportOrArrayCastShowsTheSecret(): void
    {
        $credentials = [
            FetchCredentials::clientSecretBasic('client', self::SECRET),
            FetchCredentials::clientSecretPost('client', self::SECRET),
            FetchCredentials::privateKeyJwt('client', self::SECRET),
            FetchCredentials::accessToken(self::SECRET),
        ];

        foreach ($credentials as $credential) {
            foreach (self::shown($credential) as $shown) {
                self::assertStringNotContainsString(self::SECRET, $shown);
            }

            self::assertSame(self::SECRET, $credential->secret());
        }
    }

    /**
     * An access token is sent in a header, so one that is not an RFC 6750
     * b64token (a control character, a space, a quote) is refused, and the
     * message never names it.
     *
     * @return void
     */
    public function testRefusesAnAccessTokenThatIsNotAB64Token(): void
    {
        foreach (["the-token\r\nX-Injected: 1", "the-token\x01", 'the token', 'the"token', '=the-token', "the-token==\n"] as $token) {
            try {
                FetchCredentials::accessToken($token);

                self::fail('Expected the access token to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An access token must be an RFC 6750 b64token.', $exception->getMessage());
                self::assertStringNotContainsString('the-token', $exception->getMessage());
            }
        }

        self::assertSame('eyJ.a-b_c~d+e/f==', FetchCredentials::accessToken('eyJ.a-b_c~d+e/f==')->secret());
    }

    /**
     * It refuses to be serialised, so it cannot reach a queue or a cache.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Outbound credentials cannot be serialised.');

        serialize(FetchCredentials::clientSecretPost('client', self::SECRET));
    }

    /**
     * It refuses to be unserialised, so a crafted payload cannot build one.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Outbound credentials cannot be unserialised.');

        FetchCredentials::clientSecretPost('client', self::SECRET)->__unserialize([]);
    }

    /**
     * What a value looks like through each way PHP and Laravel's tooling show
     * an object: Symfony's VarDumper (behind `dump()` and `dd()`), `print_r()`,
     * `var_export()` and an array cast.
     *
     * @param  object  $value
     * @return list<string>
     */
    private static function shown(object $value): array
    {
        return [
            (string) (new CliDumper)->dump((new VarCloner)->cloneVar($value), true),
            print_r($value, true),
            var_export($value, true),
            print_r((array) $value, true),
            (string) json_encode((array) $value),
        ];
    }
}
