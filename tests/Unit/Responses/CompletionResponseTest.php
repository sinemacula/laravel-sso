<?php

declare(strict_types = 1);

namespace Tests\Unit\Responses;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Translation\Translator as TranslatorContract;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Localization\Messages;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for the responses a completion answers with: a `303` after a POST
 * and a `302` after a GET, never a `307` or a `308`; the code or the failure
 * code, then the reference, in the fragment or the query of the redirect URI,
 * otherwise unchanged; a `400` or a `429` with no redirect; the same headers on
 * every one; the body a message; the code never in a dump and never serialised;
 * and nothing caught.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionResponse::class)]
#[CoversClass(CompletionResponses::class)]
final class CompletionResponseTest extends TestCase
{
    /** @var string A public reference holding both `-` and `_`. */
    private const string REFERENCE = 'Ab-_Ab-_Ab-_Ab-_Ab-_Ab-_Ab-_Ab-_';

    /** @var string A handoff code holding both `-` and `_`. */
    private const string CODE = 'Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_xyz';

    /** @var string The line of the `400` and the `429`, in the test's English. */
    private const string INVALID = 'Invalid line.';

    /** @var string The line of a redirect, in the test's English. */
    private const string REDIRECTING = 'Redirecting line.';

    /** @var array<string, string> The headers every response is sent with. */
    private const array HEADERS = [
        'Cache-Control'   => 'no-store',
        'Referrer-Policy' => 'no-referrer',
        'Content-Type'    => 'text/plain; charset=UTF-8',
    ];

    /**
     * The headers every response is sent with.
     *
     * @return void
     */
    public function testTheHeadersEveryResponseIsSentWith(): void
    {
        self::assertSame(self::HEADERS, CompletionResponse::HEADERS);
        self::assertSame([302, 303, 400, 429], [CompletionResponse::FOUND, CompletionResponse::SEE_OTHER, CompletionResponse::BAD_REQUEST, CompletionResponse::TOO_MANY_REQUESTS]);
    }

    /**
     * Rows of `[outcome, method, status]`.
     *
     * @return iterable<string, array{string, string, int}>
     */
    public static function provideStatuses(): iterable
    {
        $redirects = ['POST' => 303, 'GET' => 302, 'HEAD' => 303, 'get' => 302, 'post' => 303, 'PUT' => 303, '' => 303];

        foreach (['completed', 'failed', 'reinitiated'] as $outcome) {
            foreach ($redirects as $method => $status) {
                yield sprintf('%s after "%s"', $outcome, $method) => [$outcome, $method, $status];
            }
        }

        foreach (['POST', 'GET', 'HEAD'] as $method) {
            yield sprintf('rejected after "%s"', $method) => ['rejected', $method, 400];
            yield sprintf('rate limited after "%s"', $method) => ['rate_limited', $method, 429];
        }
    }

    /**
     * Each outcome answers with its status for each method: a redirect is a
     * `303` after a POST, a `302` after a GET, in any case, and a `303` after
     * any other method; a refusal is a `400` or a `429` whatever the method.
     *
     * @param  string  $outcome
     * @param  string  $method
     * @param  int  $status
     * @return void
     */
    #[DataProvider('provideStatuses')]
    public function testEachOutcomeAnswersWithItsStatus(string $outcome, string $method, int $status): void
    {
        self::assertSame($status, self::responses()->from(self::outcome($outcome), $method)->status);
    }

    /**
     * No outcome after any method answers with a `307` or a `308`, which would
     * forward the posted body.
     *
     * @return void
     */
    public function testNeverA307OrA308(): void
    {
        $answered = [];

        foreach (['completed', 'failed', 'reinitiated', 'rejected', 'rate_limited'] as $outcome) {
            foreach (['GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'get', 'post', ''] as $method) {
                $status = self::responses()->from(self::outcome($outcome), $method)->status;

                self::assertNotContains($status, [307, 308]);

                $answered[$status] = true;
            }
        }

        ksort($answered);

        self::assertSame([302, 303, 400, 429], array_keys($answered));
    }

    /**
     * Rows of `[redirect URI, delivery, location]` for a completed one.
     *
     * @return iterable<string, array{string, \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery, string}>
     */
    public static function provideCompletedLocations(): iterable
    {
        $parameters = 'code=' . self::CODE . '&reference=' . self::REFERENCE;

        foreach (self::redirectUris() as $name => [$uri, $fragment, $query]) {
            yield $name . ', in the fragment' => [$uri, HandoffDelivery::FRAGMENT, $fragment . $parameters];
            yield $name . ', in the query' => [$uri, HandoffDelivery::QUERY, $query . $parameters];
        }
    }

    /**
     * A completed one redirects to the redirect URI, otherwise unchanged, with
     * the code and then the reference in the fragment or the query.
     *
     * @param  string  $redirectUri
     * @param  \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery  $delivery
     * @param  string  $location
     * @return void
     */
    #[DataProvider('provideCompletedLocations')]
    public function testACompletedOneCarriesTheCodeAndTheReference(string $redirectUri, HandoffDelivery $delivery, string $location): void
    {
        $result = CompletionResult::completed($redirectUri, $delivery, self::reference(), self::handoff());

        self::assertResponse([303, self::HEADERS, $location, self::REDIRECTING], self::responses()->from($result, 'POST'));
        self::assertResponse([302, self::HEADERS, $location, self::REDIRECTING], self::responses()->from($result, 'GET'));
    }

    /**
     * Rows of `[redirect URI, delivery, location]` for a failed one.
     *
     * @return iterable<string, array{string, \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery, string}>
     */
    public static function provideFailedLocations(): iterable
    {
        $parameters = 'error=request_expired&reference=' . self::REFERENCE;

        foreach (self::redirectUris() as $name => [$uri, $fragment, $query]) {
            yield $name . ', in the fragment' => [$uri, HandoffDelivery::FRAGMENT, $fragment . $parameters];
            yield $name . ', in the query' => [$uri, HandoffDelivery::QUERY, $query . $parameters];
        }
    }

    /**
     * A failed one redirects to the same URI, otherwise unchanged, with the
     * failure code and then the reference in the fragment or the query.
     *
     * @param  string  $redirectUri
     * @param  \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery  $delivery
     * @param  string  $location
     * @return void
     */
    #[DataProvider('provideFailedLocations')]
    public function testAFailedOneCarriesTheFailureCodeAndTheReference(string $redirectUri, HandoffDelivery $delivery, string $location): void
    {
        $result = CompletionResult::failed(FailureReason::REQUEST_EXPIRED, $redirectUri, $delivery, self::reference());

        self::assertResponse([303, self::HEADERS, $location, self::REDIRECTING], self::responses()->from($result, 'POST'));
        self::assertResponse([302, self::HEADERS, $location, self::REDIRECTING], self::responses()->from($result, 'GET'));
    }

    /**
     * Every failure reason is carried as its code, which needs no
     * percent-encoding, and nothing else: no reason in prose, no description
     * and no assertion.
     *
     * @return void
     */
    public function testEveryFailureReasonIsCarriedAsItsCode(): void
    {
        foreach (FailureReason::cases() as $reason) {
            $fragment = CompletionResult::failed($reason, 'https://app.example.com/sso', HandoffDelivery::FRAGMENT, self::reference());
            $query    = CompletionResult::failed($reason, 'https://app.example.com/sso', HandoffDelivery::QUERY, self::reference());

            self::assertSame(rawurlencode($reason->value), $reason->value);
            self::assertSame('https://app.example.com/sso#error=' . $reason->value . '&reference=' . self::REFERENCE, self::responses()->from($fragment, 'POST')->location());
            self::assertSame('https://app.example.com/sso?error=' . $reason->value . '&reference=' . self::REFERENCE, self::responses()->from($query, 'POST')->location());
            self::assertSame(self::REDIRECTING, self::responses()->from($fragment, 'POST')->body);
        }
    }

    /**
     * A re-initiated one redirects to the start URL exactly as given.
     *
     * @return void
     */
    public function testAReinitiatedOneRedirectsToTheStartUrlExactly(): void
    {
        $startUrl = 'https://app.example.com/sso/start?connection=01jabcdefghjkmnpqrstvwxyz0&note=a%20b#top';
        $result   = CompletionResult::reinitiated($startUrl);

        self::assertResponse([303, self::HEADERS, $startUrl, self::REDIRECTING], self::responses()->from($result, 'POST'));
        self::assertResponse([302, self::HEADERS, $startUrl, self::REDIRECTING], self::responses()->from($result, 'GET'));
        self::assertResponse([303, self::HEADERS, $startUrl, self::REDIRECTING], self::responses()->from($result, 'HEAD'));
    }

    /**
     * A rejected one is a `400` with no redirect and the same body whatever the
     * reason or the method.
     *
     * @return void
     */
    public function testARejectedOneIsA400WithNoRedirect(): void
    {
        foreach ([FailureReason::REQUEST_UNKNOWN, FailureReason::CONNECTION_UNAVAILABLE, FailureReason::CONNECTION_MISMATCH] as $reason) {
            foreach (['POST', 'GET', 'HEAD'] as $method) {
                self::assertResponse([400, self::HEADERS, null, self::INVALID], self::responses()->from(CompletionResult::rejected($reason), $method));
            }
        }
    }

    /**
     * A rate limited one is a `429` with `Retry-After` and no redirect.
     *
     * @return void
     */
    public function testARateLimitedOneIsA429WithRetryAfter(): void
    {
        $headers = [...self::HEADERS, 'Retry-After' => '30'];

        self::assertResponse([429, $headers, null, self::INVALID], self::responses()->from(CompletionResult::rateLimited(30), 'POST'));
        self::assertResponse([429, $headers, null, self::INVALID], self::responses()->from(CompletionResult::rateLimited(30), 'GET'));
        self::assertResponse([429, [...self::HEADERS, 'Retry-After' => '1'], null, self::INVALID], self::responses()->from(CompletionResult::rateLimited(1), 'POST'));
    }

    /**
     * The body is read in the translator's current locale.
     *
     * @return void
     */
    public function testTheBodyIsReadInTheCurrentLocale(): void
    {
        $loader = self::loader();
        $loader->addMessages('fr', 'messages', ['completion' => ['invalid' => 'Ligne invalide.', 'redirecting' => 'Ligne de retour.']], 'sso');

        $translator = new Translator($loader, 'fr');
        $responses  = new CompletionResponses(new Messages($translator));

        self::assertSame('Ligne invalide.', $responses->from(CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN), 'POST')->body);
        self::assertSame('Ligne de retour.', $responses->from(self::outcome('completed'), 'POST')->body);

        $translator->setLocale('en');

        self::assertSame(self::INVALID, $responses->from(CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN), 'POST')->body);
    }

    /**
     * Rows of `[status, accepted]`.
     *
     * @return iterable<string, array{int, bool}>
     */
    public static function provideRedirectStatuses(): iterable
    {
        foreach ([200 => false, 301 => false, 302 => true, 303 => true, 304 => false, 307 => false, 308 => false] as $status => $accepted) {
            yield (string) $status => [$status, $accepted];
        }
    }

    /**
     * A redirect is only ever a `302` or a `303`.
     *
     * @param  int  $status
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideRedirectStatuses')]
    public function testARedirectIsOnlyA302OrA303(int $status, bool $accepted): void
    {
        if (!$accepted) {
            $this->expectExceptionObject(new \InvalidArgumentException('A completion redirects with a 302 or a 303, never another status.'));
        }

        $response = CompletionResponse::redirect($status, 'https://app.example.com/sso', 'Body.');

        self::assertResponse([$status, self::HEADERS, 'https://app.example.com/sso', 'Body.'], $response);
    }

    /**
     * Rows of `[retry after]` too short to be a wait.
     *
     * @return iterable<string, array{int}>
     */
    public static function provideTooShortWaits(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
    }

    /**
     * A rate limited response waits at least one second.
     *
     * @param  int  $retryAfter
     * @return void
     */
    #[DataProvider('provideTooShortWaits')]
    public function testARateLimitedResponseWaitsAtLeastOneSecond(int $retryAfter): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('A rate limited completion waits at least one second.'));

        CompletionResponse::rateLimited($retryAfter, 'Body.');
    }

    /**
     * A refusal built directly carries what it was given and no redirect.
     *
     * @return void
     */
    public function testARefusalBuiltDirectly(): void
    {
        self::assertResponse([400, self::HEADERS, null, 'Refused.'], CompletionResponse::rejected('Refused.'));
        self::assertResponse([429, [...self::HEADERS, 'Retry-After' => '1'], null, 'Wait.'], CompletionResponse::rateLimited(1, 'Wait.'));
        self::assertResponse([429, [...self::HEADERS, 'Retry-After' => '2'], null, 'Wait.'], CompletionResponse::rateLimited(2, 'Wait.'));
    }

    /**
     * Rows of `[redirect URI, delivery, location as a dump shows it]`.
     *
     * @return iterable<string, array{string, \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery, string}>
     */
    public static function provideShownLocations(): iterable
    {
        $reference = '&reference=' . self::REFERENCE;

        yield 'in the fragment' => ['https://app.example.com/sso', HandoffDelivery::FRAGMENT, 'https://app.example.com/sso#code=[redacted]' . $reference];
        yield 'in the fragment, after a query' => ['https://app.example.com/sso?t=a', HandoffDelivery::FRAGMENT, 'https://app.example.com/sso?t=a#code=[redacted]' . $reference];
        yield 'in the query' => ['https://app.example.com/sso', HandoffDelivery::QUERY, 'https://app.example.com/sso?code=[redacted]' . $reference];
        yield 'in the query, after another parameter' => ['com.example.app:/sso?tenant=a', HandoffDelivery::QUERY, 'com.example.app:/sso?tenant=a&code=[redacted]' . $reference];
    }

    /**
     * A dump and `json_encode()` show the location with the code redacted,
     * wherever the code is, while `location()` still reveals it.
     *
     * @param  string  $redirectUri
     * @param  \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery  $delivery
     * @param  string  $shown
     * @return void
     */
    #[DataProvider('provideShownLocations')]
    public function testADumpHidesTheCode(string $redirectUri, HandoffDelivery $delivery, string $shown): void
    {
        $response = self::responses()->from(CompletionResult::completed($redirectUri, $delivery, self::reference(), self::handoff()), 'POST');
        $dump     = ['status' => 303, 'headers' => self::HEADERS, 'location' => $shown, 'body' => self::REDIRECTING];

        self::assertSame($dump, $response->__debugInfo());
        self::assertSame($dump, $response->jsonSerialize());
        self::assertSame(json_encode($dump), json_encode($response));
        self::assertStringContainsString(self::CODE, (string) $response->location());

        $dumped = (string) (new CliDumper)->dump((new VarCloner)->cloneVar($response), true);

        foreach ([print_r($response, true), var_export($response, true), $dumped, (string) json_encode($response)] as $output) {
            self::assertStringNotContainsString(self::CODE, $output);
            self::assertStringNotContainsString('Cd-_', $output);
        }
    }

    /**
     * A failed one, a re-initiated one and a refusal show what they carry, with
     * nothing to redact.
     *
     * @return void
     */
    public function testADumpOfAResponseWithoutACode(): void
    {
        $failed = self::responses()->from(self::outcome('failed'), 'GET');

        self::assertSame([
            'status'   => 302,
            'headers'  => self::HEADERS,
            'location' => 'https://app.example.com/sso#error=request_expired&reference=' . self::REFERENCE,
            'body'     => self::REDIRECTING,
        ], $failed->__debugInfo());
        self::assertSame([
            'status'   => 303,
            'headers'  => self::HEADERS,
            'location' => 'https://app.example.com/sso/start?connection=01jabcdefghjkmnpqrstvwxyz0',
            'body'     => self::REDIRECTING,
        ], self::responses()->from(self::outcome('reinitiated'), 'POST')->__debugInfo());
        self::assertSame([
            'status'   => 429,
            'headers'  => [...self::HEADERS, 'Retry-After' => '30'],
            'location' => null,
            'body'     => self::INVALID,
        ], self::responses()->from(self::outcome('rate_limited'), 'POST')->__debugInfo());
    }

    /**
     * A response refuses to be serialised.
     *
     * @return void
     */
    public function testRefusesToBeSerialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A completion response cannot be serialised.'));

        serialize(self::responses()->from(self::outcome('completed'), 'POST'));
    }

    /**
     * A response refuses to be unserialised.
     *
     * @return void
     */
    public function testRefusesToBeUnserialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A completion response cannot be unserialised.'));

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(CompletionResponse::class), CompletionResponse::class));
    }

    /**
     * The builder catches nothing: an error reading a message propagates as it
     * was thrown, whatever the outcome, and never becomes a failure redirect.
     *
     * @return void
     */
    public function testAnErrorReadingAMessagePropagates(): void
    {
        $error      = new \RuntimeException('The translations could not be read.');
        $translator = self::createStub(TranslatorContract::class);

        $translator->method('getLocale')->willReturn('en');
        $translator->method('get')->willThrowException($error);

        $responses = new CompletionResponses(new Messages($translator));

        foreach (['completed', 'failed', 'reinitiated', 'rejected', 'rate_limited'] as $outcome) {
            try {
                $responses->from(self::outcome($outcome), 'POST');

                self::fail(sprintf('A %s outcome caught the error.', $outcome));
            } catch (\RuntimeException $caught) {
                self::assertSame($error, $caught);
            }
        }
    }

    /**
     * A message missing in English is the package's bug, and propagates too.
     *
     * @return void
     */
    public function testAMissingMessagePropagates(): void
    {
        $responses = new CompletionResponses(new Messages(new Translator(new ArrayLoader, 'en')));

        $this->expectExceptionObject(new \LogicException('The package has no English line for the message sso::messages.completion.invalid.'));

        $responses->from(CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN), 'POST');
    }

    /**
     * Rows of `name => [redirect URI, location before a fragment's parameters,
     * location before a query's parameters]`: an https URI with and without a
     * path, a trailing slash or a query, and a private-use scheme.
     *
     * @return array<string, array{string, string, string}>
     */
    private static function redirectUris(): array
    {
        return [
            'an https URI'                         => ['https://app.example.com/sso', 'https://app.example.com/sso#', 'https://app.example.com/sso?'],
            'an https URI with a query'            => ['https://app.example.com/sso?tenant=a', 'https://app.example.com/sso?tenant=a#', 'https://app.example.com/sso?tenant=a&'],
            'an https URI with an empty query'     => ['https://app.example.com/sso?', 'https://app.example.com/sso?#', 'https://app.example.com/sso?&'],
            'an https URI without a path'          => ['https://app.example.com', 'https://app.example.com#', 'https://app.example.com?'],
            'an https URI with a trailing slash'   => ['https://app.example.com/sso/', 'https://app.example.com/sso/#', 'https://app.example.com/sso/?'],
            'a private-use scheme'                 => ['com.example.app:/sso', 'com.example.app:/sso#', 'com.example.app:/sso?'],
            'a private-use scheme with a query'    => ['com.example.app:/sso?tenant=a', 'com.example.app:/sso?tenant=a#', 'com.example.app:/sso?tenant=a&'],
            'a loopback URI with a port and query' => ['http://127.0.0.1:8123/cb?a=1&b=2', 'http://127.0.0.1:8123/cb?a=1&b=2#', 'http://127.0.0.1:8123/cb?a=1&b=2&'],
        ];
    }

    /**
     * Assert the response's status, headers, location and body, together.
     *
     * @param  array{int, array<string, string>, ?string, string}  $expected
     * @param  \SineMacula\Laravel\Sso\Responses\CompletionResponse  $response
     * @return void
     */
    private static function assertResponse(array $expected, CompletionResponse $response): void
    {
        self::assertSame($expected, [$response->status, $response->headers, $response->location(), $response->body]);
    }

    /**
     * A completion result of the outcome named.
     *
     * @param  string  $outcome
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private static function outcome(string $outcome): CompletionResult
    {
        return match ($outcome) {
            'completed'   => CompletionResult::completed('https://app.example.com/sso', HandoffDelivery::FRAGMENT, self::reference(), self::handoff()),
            'failed'      => CompletionResult::failed(FailureReason::REQUEST_EXPIRED, 'https://app.example.com/sso', HandoffDelivery::FRAGMENT, self::reference()),
            'reinitiated' => CompletionResult::reinitiated('https://app.example.com/sso/start?connection=01jabcdefghjkmnpqrstvwxyz0'),
            'rejected'    => CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN),
            default       => CompletionResult::rateLimited(30),
        };
    }

    /**
     * The responses, reading the test's English lines.
     *
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponses
     */
    private static function responses(): CompletionResponses
    {
        return new CompletionResponses(new Messages(new Translator(self::loader(), 'en')));
    }

    /**
     * A loader holding the test's English lines under the `sso` namespace.
     *
     * @return \Illuminate\Translation\ArrayLoader
     */
    private static function loader(): ArrayLoader
    {
        $loader = new ArrayLoader;
        $loader->addMessages('en', 'messages', ['completion' => ['invalid' => self::INVALID, 'redirecting' => self::REDIRECTING]], 'sso');

        return $loader;
    }

    /**
     * The request's public reference.
     *
     * @return \SineMacula\Laravel\Sso\Flows\RequestReference
     */
    private static function reference(): RequestReference
    {
        return RequestReference::fromString(self::REFERENCE);
    }

    /**
     * The handoff issued.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
     */
    private static function handoff(): IssuedHandoff
    {
        return new IssuedHandoff(HandoffCode::fromString(self::CODE), CarbonImmutable::parse('2026-11-01T10:01:00Z'));
    }
}
