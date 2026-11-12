<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Enums\NavigationType;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for the navigation a started flow answers with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Navigation::class)]
#[CoversClass(NavigationType::class)]
final class NavigationTest extends TestCase
{
    use DumpsValues;

    /** @var string An OIDC authorisation request's URL, with its state, nonce and challenge. */
    private const string OIDC_URL = 'https://idp.example.com/authorize?response_type=code&client_id=client-123'
        . '&state=the-oidc-state-value&nonce=the-oidc-nonce-value&code_challenge=the-oidc-challenge-value&code_challenge_method=S256';

    /** @var string What a dump shows of the OIDC request's URL. */
    private const string OIDC_DUMPED = 'https://idp.example.com/authorize?response_type=[redacted]&client_id=[redacted]'
        . '&state=[redacted]&nonce=[redacted]&code_challenge=[redacted]&code_challenge_method=[redacted]';

    /** @var array<string, string> A SAML HTTP-POST form's fields. */
    private const array SAML_FIELDS = ['SAMLRequest' => 'PHNhbWxwOkF1dGhuUmVxdWVzdCB0aGUtc2FtbC1yZXF1ZXN0', 'RelayState' => 'the-saml-relay-state'];

    /** @var list<string> The protocol values no dump may show. */
    private const array PROTOCOL_VALUES = [
        'client-123',
        'the-oidc-state-value',
        'the-oidc-nonce-value',
        'the-oidc-challenge-value',
        'PHNhbWxwOkF1dGhuUmVxdWVzdCB0aGUtc2FtbC1yZXF1ZXN0',
        'the-saml-relay-state',
    ];

    /**
     * A redirect carries its URL and no fields, and serialises as
     * `{type: redirect, url}`.
     *
     * @return void
     */
    public function testARedirectCarriesItsUrl(): void
    {
        $navigation = Navigation::redirect('https://idp.example.com/sso?SAMLRequest=abc');

        self::assertSame(NavigationType::REDIRECT, $navigation->type);
        self::assertTrue($navigation->isRedirect());
        self::assertFalse($navigation->isPost());
        self::assertSame([], $navigation->fields());
        self::assertSame('https://idp.example.com/sso?SAMLRequest=abc', $navigation->url());
        self::assertSame(['type' => 'redirect', 'url' => 'https://idp.example.com/sso?SAMLRequest=abc'], $navigation->jsonSerialize());
    }

    /**
     * A post carries its action and its fields, and serialises as
     * `{type: post, url, fields}`.
     *
     * @return void
     */
    public function testAPostCarriesItsActionAndFields(): void
    {
        $navigation = Navigation::post('https://idp.example.com/sso', ['SAMLRequest' => 'abc', 'RelayState' => 'xyz']);

        self::assertSame(NavigationType::POST, $navigation->type);
        self::assertTrue($navigation->isPost());
        self::assertFalse($navigation->isRedirect());
        self::assertSame('https://idp.example.com/sso', $navigation->url());
        self::assertSame(['SAMLRequest' => 'abc', 'RelayState' => 'xyz'], $navigation->fields());
        self::assertSame([
            'type'   => 'post',
            'url'    => 'https://idp.example.com/sso',
            'fields' => ['SAMLRequest' => 'abc', 'RelayState' => 'xyz'],
        ], $navigation->jsonSerialize());
        self::assertSame('{"type":"post","url":"https:\/\/idp.example.com\/sso","fields":{"SAMLRequest":"abc","RelayState":"xyz"}}', json_encode($navigation));
    }

    /**
     * A URL's scheme is read whatever its case.
     *
     * @return void
     */
    public function testAcceptsAnHttpsSchemeInAnyCase(): void
    {
        self::assertSame(['type' => 'redirect', 'url' => 'HTTPS://idp.example.com/sso'], Navigation::redirect('HTTPS://idp.example.com/sso')->jsonSerialize());
    }

    /**
     * Rows of `[url]`: URLs a navigation never leads to.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedUrls(): iterable
    {
        yield from [
            'empty'        => [''],
            'relative'     => ['/sso'],
            'http'         => ['http://idp.example.com/sso'],
            'javascript'   => ['javascript:alert(1)'],
            'no host'      => ['https:///sso'],
            'a path alone' => ['https:/sso'],
            'another kind' => ['ftp://idp.example.com/sso'],
        ];
    }

    /**
     * A URL that is not absolute `https` is refused, for a redirect and a post.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideRefusedUrls')]
    public function testRefusesAUrlThatIsNotAbsoluteHttps(string $url): void
    {
        foreach ([static fn (): Navigation => Navigation::redirect($url), static fn (): Navigation => Navigation::post($url, [])] as $build) {

            try {
                $build();
                self::fail('The URL was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A navigation leads to an absolute https URL.', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[fields]`: form fields refused.
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideRefusedFields(): iterable
    {
        yield from [
            'a numeric name' => [['abc']],
            'an empty name'  => [['' => 'abc']],
            'a list value'   => [['SAMLRequest' => ['abc']]],
            'a number value' => [['SAMLRequest' => 1]],
        ];
    }

    /**
     * A posted field must be a string under a non-empty name.
     *
     * @param  array<array-key, mixed>  $fields
     * @return void
     */
    #[DataProvider('provideRefusedFields')]
    public function testRefusesAFieldThatIsNotANamedString(array $fields): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A posted form\'s fields are strings, each under a non-empty name.');

        Navigation::post('https://idp.example.com/sso', $fields);
    }

    /**
     * Rows of `[url, dumped]`: a redirect's URL, and the URL its dump shows,
     * every query value and any fragment redacted.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideDumpedUrls(): iterable
    {
        yield from [
            'no query'                   => ['https://idp.example.com/authorize', 'https://idp.example.com/authorize'],
            'an OIDC request'            => [self::OIDC_URL, self::OIDC_DUMPED],
            'an empty query'             => ['https://idp.example.com/a?', 'https://idp.example.com/a?'],
            'a name with no value'       => ['https://idp.example.com/a?flag&empty=', 'https://idp.example.com/a?flag&empty=[redacted]'],
            'a value holding = and ?'    => ['https://idp.example.com/a?next=/b?c=d=e&state=s', 'https://idp.example.com/a?next=[redacted]&state=[redacted]'],
            'a fragment'                 => ['https://idp.example.com/a?state=s#code=c', 'https://idp.example.com/a?state=[redacted]#[redacted]'],
            'a fragment holding ? and #' => ['https://idp.example.com/a#x?state=s#y', 'https://idp.example.com/a#[redacted]'],
        ];
    }

    /**
     * A redirect's dump redacts every query value and fragment, while its URL
     * and serialised form keep the URL whole.
     *
     * @param  string  $url
     * @param  string  $dumped
     * @return void
     */
    #[DataProvider('provideDumpedUrls')]
    public function testARedirectsDumpRedactsEveryQueryValueAndFragment(string $url, string $dumped): void
    {
        $navigation = Navigation::redirect($url);

        self::assertSame(['type' => 'redirect', 'url' => $dumped], $navigation->__debugInfo());
        self::assertSame($url, $navigation->url());
        self::assertSame(['type' => 'redirect', 'url' => $url], $navigation->jsonSerialize());
    }

    /**
     * A post's dump shows its type, its action and its fields' names, never a
     * field's value, while its fields and its serialised form carry them whole.
     *
     * @return void
     */
    public function testAPostsDumpShowsItsFieldNamesOnly(): void
    {
        $navigation = Navigation::post('https://idp.example.com/sso?tenant=acme', self::SAML_FIELDS);

        self::assertSame([
            'type'   => 'post',
            'url'    => 'https://idp.example.com/sso?tenant=[redacted]',
            'fields' => ['SAMLRequest' => '[redacted]', 'RelayState' => '[redacted]'],
        ], $navigation->__debugInfo());
        self::assertSame(['type' => 'post', 'url' => 'https://idp.example.com/sso?tenant=acme', 'fields' => self::SAML_FIELDS], $navigation->jsonSerialize());
    }

    /**
     * No dump by PHP's dumpers or Symfony's VarDumper shows a query value or a
     * field's value.
     *
     * @return void
     */
    public function testNoDumpShowsAProtocolValue(): void
    {
        foreach ([Navigation::redirect(self::OIDC_URL), Navigation::post('https://idp.example.com/sso', self::SAML_FIELDS)] as $navigation) {

            foreach (self::dumps($navigation) as $dumper => $dumped) {

                self::assertStringContainsString('Navigation', $dumped, $dumper);

                foreach (self::PROTOCOL_VALUES as $value) {
                    self::assertStringNotContainsString($value, $dumped, "{$dumper} shows [{$value}].");
                }
            }
        }
    }

    /**
     * A navigation back to the application accepts only an exact registered
     * redirect URI.
     *
     * @return void
     */
    public function testANavigationBackToTheApplication(): void
    {
        foreach (['com.example.app:/sign-in', 'http://127.0.0.1:8080/sign-in', 'https://app.example.com/sign-in?x=1'] as $url) {

            $navigation = Navigation::toApplication($url);

            self::assertTrue($navigation->isRedirect());
            self::assertSame(['type' => 'redirect', 'url' => $url], $navigation->jsonSerialize());
        }

        $this->expectExceptionObject(new \InvalidArgumentException(
            '`navigation` must be an exact redirect URI: an absolute https URL (or http on 127.0.0.1 or [::1]), or a private-use scheme with a dot'
            . ' (`com.example.app:/callback`), with no user information, fragment or wildcard.',
        ));

        Navigation::toApplication('http://app.example.com/sign-in');
    }
}
