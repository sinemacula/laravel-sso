<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Enums\NavigationType;
use SineMacula\Laravel\Sso\Protocols\Navigation;

/**
 * Unit tests for the navigation a started flow answers with: a redirect or a
 * posted form, to an absolute `https` URL, serialised as SSO-12.5's
 * `navigation`.
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
        self::assertSame([], $navigation->fields);
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
        self::assertSame([
            'type'   => 'post',
            'url'    => 'https://idp.example.com/sso',
            'fields' => ['SAMLRequest' => 'abc', 'RelayState' => 'xyz'],
        ], $navigation->jsonSerialize());
        self::assertSame('{"type":"post","url":"https:\/\/idp.example.com\/sso","fields":{"SAMLRequest":"abc","RelayState":"xyz"}}', json_encode($navigation));
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
}
