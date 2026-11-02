<?php

declare(strict_types = 1);

namespace Tests\Unit\Fetching;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for an outbound request: each purpose with the only credential it
 * may carry, a token request authenticated by exactly one method, and a form
 * that a dump and serialisation never show.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FetchRequest::class)]
#[CoversClass(FetchPurpose::class)]
final class FetchRequestTest extends TestCase
{
    /** @var string A URL the requests name. */
    private const string URL = 'https://idp.example.com/endpoint';

    /**
     * Metadata, discovery and a JWKS are fetched with `GET` and no credential,
     * and may follow a checked redirect.
     *
     * @return void
     */
    public function testUncredentialedPurposesCarryNothing(): void
    {
        foreach ([FetchRequest::metadata(self::URL), FetchRequest::discovery(self::URL), FetchRequest::jwks(self::URL)] as $request) {
            self::assertSame(self::URL, $request->url);
            self::assertSame('GET', $request->method());
            self::assertSame([], $request->form());
            self::assertNull($request->credentials);
            self::assertFalse($request->purpose->isCredentialed());
        }

        self::assertSame(
            [FetchPurpose::METADATA, FetchPurpose::DISCOVERY, FetchPurpose::JWKS],
            [FetchRequest::metadata(self::URL)->purpose, FetchRequest::discovery(self::URL)->purpose, FetchRequest::jwks(self::URL)->purpose],
        );
    }

    /**
     * Every request may carry a size cap of its own, of at least a byte, shown
     * by a dump; one given none carries none.
     *
     * @return void
     */
    public function testARequestCarriesItsOwnCap(): void
    {
        $client = FetchCredentials::clientSecretBasic('client', 'secret');
        $bearer = FetchCredentials::accessToken('token');

        self::assertSame(1, FetchRequest::metadata(self::URL, 1)->maxBytes);
        self::assertSame(268435456, FetchRequest::metadata(self::URL, 268435456)->maxBytes);
        self::assertSame(4096, FetchRequest::metadata(self::URL, 4096)->__debugInfo()['max_bytes']);
        self::assertSame(
            [2, 3, 4, 5],
            [
                FetchRequest::discovery(self::URL, 2)->maxBytes,
                FetchRequest::jwks(self::URL, 3)->maxBytes,
                FetchRequest::token(self::URL, [], $client, null, 4)->maxBytes,
                FetchRequest::userInfo(self::URL, $bearer, null, 5)->maxBytes,
            ],
        );
        self::assertSame(
            [null, null, null, null, null],
            [
                FetchRequest::metadata(self::URL)->maxBytes,
                FetchRequest::discovery(self::URL)->maxBytes,
                FetchRequest::jwks(self::URL)->maxBytes,
                FetchRequest::token(self::URL, [], $client)->maxBytes,
                FetchRequest::userInfo(self::URL, $bearer)->maxBytes,
            ],
        );

        foreach ([0, -1] as $maxBytes) {
            try {
                FetchRequest::jwks(self::URL, $maxBytes);
                self::fail("A cap of {$maxBytes} bytes was taken.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A request\'s own size cap is at least one byte.', $exception->getMessage());
            }
        }
    }

    /**
     * A token or UserInfo request may carry a timeout of its own, of at least a
     * second, shown by a dump; every other request, and one given none, carries
     * none.
     *
     * @return void
     */
    public function testATokenOrUserInfoRequestCarriesItsOwnTimeout(): void
    {
        $client = FetchCredentials::clientSecretBasic('client', 'secret');
        $bearer = FetchCredentials::accessToken('token');

        self::assertSame([1, 60], [FetchRequest::token(self::URL, [], $client, 1)->timeoutSeconds, FetchRequest::userInfo(self::URL, $bearer, 60)->timeoutSeconds]);
        self::assertSame(7, FetchRequest::token(self::URL, [], $client, 7)->__debugInfo()['timeout']);
        self::assertSame(
            [null, null, null, null, null],
            [
                FetchRequest::metadata(self::URL)->timeoutSeconds,
                FetchRequest::discovery(self::URL)->timeoutSeconds,
                FetchRequest::jwks(self::URL)->timeoutSeconds,
                FetchRequest::token(self::URL, [], $client)->timeoutSeconds,
                FetchRequest::userInfo(self::URL, $bearer)->timeoutSeconds,
            ],
        );

        foreach ([0, -1] as $seconds) {
            try {
                FetchRequest::userInfo(self::URL, $bearer, $seconds);
                self::fail("A timeout of {$seconds} seconds was taken.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A request\'s own timeout is at least one second.', $exception->getMessage());
            }
        }
    }

    /**
     * A token request is a `POST` of its form with the client authentication;
     * UserInfo a `GET` with the access token. Neither follows a redirect.
     *
     * @return void
     */
    public function testCredentialedPurposesCarryTheirCredential(): void
    {
        $client = FetchCredentials::clientSecretBasic('client', 'secret');
        $token  = FetchRequest::token(self::URL, ['grant_type' => 'authorization_code', 'code' => 'abc'], $client);

        self::assertSame(FetchPurpose::TOKEN, $token->purpose);
        self::assertSame('POST', $token->method());
        self::assertSame(['grant_type' => 'authorization_code', 'code' => 'abc'], $token->form());
        self::assertSame($client, $token->credentials);
        self::assertTrue($token->purpose->isCredentialed());

        $bearer   = FetchCredentials::accessToken('token');
        $userInfo = FetchRequest::userInfo(self::URL, $bearer);

        self::assertSame(FetchPurpose::USERINFO, $userInfo->purpose);
        self::assertSame('GET', $userInfo->method());
        self::assertSame([], $userInfo->form());
        self::assertSame($bearer, $userInfo->credentials);
        self::assertTrue($userInfo->purpose->isCredentialed());
    }

    /**
     * Rows of `[form field]`: each field only the client authentication sets.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedFields(): iterable
    {
        foreach (FetchRequest::RESERVED_FORM_FIELDS as $field) {
            yield $field => [$field];
        }
    }

    /**
     * A token request's form may not authenticate it a second way.
     *
     * @param  string  $field
     * @return void
     */
    #[DataProvider('provideReservedFields')]
    public function testATokenRequestIsAuthenticatedOnce(string $field): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("A token request's form may not set [{$field}]");

        FetchRequest::token(self::URL, ['code' => 'abc', $field => 'value'], FetchCredentials::clientSecretPost('client', 'secret'));
    }

    /**
     * A token request takes no access token, and UserInfo no client
     * authentication.
     *
     * @return void
     */
    public function testEachCredentialedPurposeTakesOnlyItsKind(): void
    {
        try {
            FetchRequest::token(self::URL, [], FetchCredentials::accessToken('token'));

            self::fail('Expected an access token to be refused for a token request.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A token request is authenticated by a client authentication, not an access token.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A UserInfo request carries the access token only, never the client authentication.');

        FetchRequest::userInfo(self::URL, FetchCredentials::privateKeyJwt('client', 'assertion'));
    }

    /**
     * A dump shows the form's field names, the credential's kind and the size
     * cap, never a value.
     *
     * @return void
     */
    public function testTheFormNeverLeaves(): void
    {
        $request = FetchRequest::token(self::URL, ['code' => 'the-code', 'code_verifier' => 'the-verifier'], FetchCredentials::clientSecretPost('client', 'the-secret'));

        self::assertSame(
            ['purpose' => 'token', 'url' => self::URL, 'form' => ['code', 'code_verifier'], 'credentials' => 'client_secret_post', 'max_bytes' => null, 'timeout' => null],
            $request->__debugInfo(),
        );
        self::assertSame(
            ['purpose' => 'jwks', 'url' => self::URL, 'form' => [], 'credentials' => null, 'max_bytes' => null, 'timeout' => null],
            FetchRequest::jwks(self::URL)->__debugInfo(),
        );

        $printed = print_r($request, true);

        foreach (['the-code', 'the-verifier', 'the-secret'] as $secret) {
            self::assertStringNotContainsString($secret, $printed);
            self::assertStringNotContainsString($secret, (string) json_encode($request));
        }
    }

    /**
     * No value of the form is held where a dump, an export or an array cast can
     * reach it, and the form still reaches the fetcher whole.
     *
     * @return void
     */
    public function testNoDumpExportOrArrayCastShowsTheForm(): void
    {
        $form    = ['code' => 'the-code', 'code_verifier' => 'the-verifier'];
        $request = FetchRequest::token(self::URL, $form, FetchCredentials::clientSecretPost('client', 'the-secret'));

        foreach (self::shown($request) as $shown) {
            foreach (['the-code', 'the-verifier', 'the-secret'] as $secret) {
                self::assertStringNotContainsString($secret, $shown);
            }
        }

        self::assertSame($form, $request->form());
    }

    /**
     * It refuses to be serialised, so it cannot reach a queue or a cache.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Outbound requests cannot be serialised.');

        serialize(FetchRequest::jwks(self::URL));
    }

    /**
     * It refuses to be unserialised, so a crafted payload cannot build one.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Outbound requests cannot be unserialised.');

        FetchRequest::jwks(self::URL)->__unserialize([]);
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
