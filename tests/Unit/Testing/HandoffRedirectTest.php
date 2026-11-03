<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;

/**
 * Unit tests for the redirect a completion sends the browser back with, as the
 * client reads it: the code, the reference and the failure code, from the
 * fragment or the query, the fragment winning; a value that is not a string
 * read as none; a completion with no redirect, and a code asked of a redirect
 * without one, refused with a `LogicException` saying why; and a dump that
 * never shows the code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedirect::class)]
final class HandoffRedirectTest extends TestCase
{
    /** @var string A handoff code. */
    private const string CODE = 'cOdE0123456789cOdE0123456789cOdE0123456789a';

    /** @var string The application's redirect URI. */
    private const string URI = 'https://app.example.com/sso';

    /** @var string A request's public reference. */
    private const string REFERENCE = 'Rq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /**
     * Rows of `[location, code, reference, error]`: where the redirect goes,
     * and what the client reads of it.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: ?string, 3: ?string}>
     */
    public static function provideLocations(): iterable
    {
        yield 'a code in the fragment' => ['https://app.example.com/sso#code=' . self::CODE . '&reference=' . self::REFERENCE, self::CODE, self::REFERENCE, null];
        yield 'a code in the query' => ['https://app.example.com/sso?tab=1&code=' . self::CODE . '&reference=' . self::REFERENCE, self::CODE, self::REFERENCE, null];
        yield 'a failure' => ['https://app.example.com/sso#error=signature_invalid&reference=' . self::REFERENCE, null, self::REFERENCE, 'signature_invalid'];
        yield 'the fragment over the query' => [self::URI . '?code=query&reference=query#code=' . self::CODE . '&reference=' . self::REFERENCE, self::CODE, self::REFERENCE, null];
        yield 'arrays read as none' => ['https://app.example.com/sso#code[]=a&reference[]=b&error[]=c', null, null, null];
        yield 'nothing' => ['https://app.example.com/sso', null, null, null];
    }

    /**
     * The client reads the code, the reference and the failure the location
     * names, whether given the response or its location.
     *
     * @param  string  $location
     * @param  ?string  $code
     * @param  ?string  $reference
     * @param  ?string  $error
     * @return void
     */
    #[DataProvider('provideLocations')]
    public function testReadsTheLocation(string $location, ?string $code, ?string $reference, ?string $error): void
    {
        foreach ([$location, CompletionResponse::redirect(CompletionResponse::SEE_OTHER, $location, 'Redirecting')] as $given) {

            $redirect = HandoffRedirect::from($given);

            self::assertSame([$code !== null, $reference, $error], [$redirect->hasCode(), $redirect->reference, $redirect->error]);

            if ($code === null) {
                continue;
            }

            self::assertSame($code, $redirect->code());
        }
    }

    /**
     * A completion that answered no redirect is refused, as is no location.
     *
     * @return void
     */
    public function testRefusesACompletionWithNoRedirect(): void
    {
        foreach ([CompletionResponse::rejected('Invalid'), CompletionResponse::rateLimited(30, 'Invalid'), null] as $response) {
            try {
                HandoffRedirect::from($response);
                self::fail('A completion with no redirect was read.');
            } catch (\LogicException $exception) {
                self::assertSame('The completion answered no redirect: it was rejected or rate limited.', $exception->getMessage());
            }
        }
    }

    /**
     * A redirect without a code refuses to give one, naming the failure when it
     * has one.
     *
     * @return void
     */
    public function testRefusesACodeItDoesNotCarry(): void
    {
        $messages = [];

        foreach (['https://app.example.com/sso#error=unlinked', 'https://app.example.com/sso'] as $location) {
            try {
                HandoffRedirect::from($location)->code();
            } catch (\LogicException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        self::assertSame(['The redirect carries no handoff code: the flow failed with [unlinked].', 'The redirect carries no handoff code.'], $messages);
    }

    /**
     * A dump shows the reference and the error, and whether there is a code,
     * never the code.
     *
     * @return void
     */
    public function testADumpNeverShowsTheCode(): void
    {
        $completed = HandoffRedirect::from('https://app.example.com/sso#code=' . self::CODE . '&reference=' . self::REFERENCE);
        $failed    = HandoffRedirect::from('https://app.example.com/sso#error=unlinked');

        self::assertSame(['code' => '[redacted]', 'reference' => self::REFERENCE, 'error' => null], $completed->__debugInfo());
        self::assertSame(['code' => null, 'reference' => null, 'error' => 'unlinked'], $failed->__debugInfo());
        self::assertStringNotContainsString(self::CODE, print_r($completed, true));
    }
}
