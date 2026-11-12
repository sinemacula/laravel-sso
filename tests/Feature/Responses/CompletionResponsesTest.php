<?php

declare(strict_types = 1);

namespace Tests\Feature\Responses;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

/**
 * Feature tests for the responses a completion answers with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionResponse::class)]
#[CoversClass(CompletionResponses::class)]
final class CompletionResponsesTest extends TestCase
{
    /** @var string The request's public reference. */
    private const string REFERENCE = 'Ab-_Ab-_Ab-_Ab-_Ab-_Ab-_Ab-_Ab-_';

    /** @var string The handoff code. */
    private const string CODE = 'Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_Cd-_xyz';

    /** @var string The package's English line for a completion with no trusted target. */
    private const string INVALID = 'The sign-in response could not be accepted.';

    /** @var string The package's English line for a completion's redirect. */
    private const string REDIRECTING = 'Returning you to the application.';

    /**
     * The package's English lines answer by default.
     *
     * @return void
     */
    public function testThePackagesEnglishLinesByDefault(): void
    {
        self::assertSame(self::INVALID, $this->responses()->from(CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN), 'POST')->body);
        self::assertSame(self::INVALID, $this->responses()->from(CompletionResult::rateLimited(5), 'POST')->body);
        self::assertSame(self::REDIRECTING, $this->responses()->from(self::completed(HandoffDelivery::FRAGMENT), 'POST')->body);
        self::assertSame(self::REDIRECTING, $this->responses()->from(CompletionResult::reinitiated('https://app.example.com/start'), 'GET')->body);
    }

    /**
     * An application's translation applies, and an untranslated line is
     * English.
     *
     * @return void
     */
    public function testAnApplicationsTranslationApplies(): void
    {
        $this->translator()->addLines(['messages.completion.invalid' => 'La réponse de connexion a été refusée.'], 'fr', 'sso');

        self::assertSame(self::INVALID, $this->responses()->from(CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN), 'POST')->body);

        $this->app?->setLocale('fr');

        self::assertSame('La réponse de connexion a été refusée.', $this->responses()->from(CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN), 'POST')->body);
        self::assertSame('La réponse de connexion a été refusée.', $this->responses()->from(CompletionResult::rateLimited(5), 'GET')->body);
        self::assertSame(self::REDIRECTING, $this->responses()->from(self::completed(HandoffDelivery::FRAGMENT), 'POST')->body);
    }

    /**
     * A locale with no translation falls back to English.
     *
     * @return void
     */
    public function testAnUntranslatedLocaleFallsBackToEnglish(): void
    {
        $this->app?->setLocale('de');

        self::assertSame(self::INVALID, $this->responses()->from(CompletionResult::rejected(FailureReason::CONNECTION_UNAVAILABLE), 'POST')->body);
        self::assertSame(self::REDIRECTING, $this->responses()->from(self::completed(HandoffDelivery::QUERY), 'GET')->body);
    }

    /**
     * A redirect carries exactly its status, headers, `Location` and body.
     *
     * @return void
     */
    public function testARedirectsHttpResponse(): void
    {
        $location = 'https://app.example.com/sso#code=' . self::CODE . '&reference=' . self::REFERENCE;
        $posted   = $this->responses()->from(self::completed(HandoffDelivery::FRAGMENT), 'POST')->toResponse(Request::create('/', 'POST'));
        $got      = $this->responses()->from(self::completed(HandoffDelivery::FRAGMENT), 'GET')->toResponse(Request::create('/'));

        self::assertSame(303, $posted->getStatusCode());
        self::assertSame(302, $got->getStatusCode());

        foreach ([$posted, $got] as $response) {
            self::assertSame(self::headers(['location' => [$location]]), self::headersOf($response));
            self::assertSame(self::REDIRECTING, $response->getContent());
        }
    }

    /**
     * A `400` and a `429` carry exactly their status, headers and body.
     *
     * @return void
     */
    public function testARefusalsHttpResponse(): void
    {
        $rejected = $this->responses()->from(CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN), 'POST')->toResponse(Request::create('/', 'POST'));
        $limited  = $this->responses()->from(CompletionResult::rateLimited(17), 'GET')->toResponse(Request::create('/'));

        self::assertSame(400, $rejected->getStatusCode());
        self::assertSame(self::headers([]), self::headersOf($rejected));
        self::assertSame(self::INVALID, $rejected->getContent());
        self::assertSame(429, $limited->getStatusCode());
        self::assertSame(self::headers(['retry-after' => ['17']]), self::headersOf($limited));
        self::assertSame(self::INVALID, $limited->getContent());
    }

    /**
     * A controller returns the response as it is, `303` after a POST and `302`
     * after a GET.
     *
     * @return void
     */
    public function testAControllerReturnsTheResponse(): void
    {
        $result = static fn (): CompletionResult => self::completed(HandoffDelivery::QUERY);

        Route::post('/sso/connections/{connection}/assertions', fn (Request $request): CompletionResponse => $this->responses()->from($result(), $request->getMethod()));
        Route::get('/sso/connections/{connection}/callback', fn (Request $request): CompletionResponse => $this->responses()->from($result(), $request->getMethod()));

        $location = 'https://app.example.com/sso?code=' . self::CODE . '&reference=' . self::REFERENCE;

        $this->post('/sso/connections/01jabcdefghjkmnpqrstvwxyz0/assertions', ['SAMLResponse' => 'PHNhbWxwOlJlc3BvbnNlLz4='])
            ->assertStatus(303)
            ->assertHeader('Location', $location)
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->assertHeader('Content-Type', 'text/plain; charset=UTF-8')
            ->assertContent(self::REDIRECTING);

        $this->get('/sso/connections/01jabcdefghjkmnpqrstvwxyz0/callback?code=abc&state=xyz')
            ->assertStatus(302)
            ->assertHeader('Location', $location)
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertHeader('Referrer-Policy', 'no-referrer');
    }

    /**
     * The headers of an HTTP response but Symfony's `Date`, by name.
     *
     * @param  \Symfony\Component\HttpFoundation\Response  $response
     * @return array<string, list<?string>>
     */
    private static function headersOf(Response $response): array
    {
        $headers = $response->headers->all();

        unset($headers['date']);
        ksort($headers);

        return $headers;
    }

    /**
     * Every completion response's headers as Symfony holds them, plus those
     * given.
     *
     * @param  array<string, list<string>>  $more
     * @return array<string, list<string>>
     */
    private static function headers(array $more): array
    {
        $headers = [
            'cache-control'   => ['no-store, private'],
            'content-type'    => ['text/plain; charset=UTF-8'],
            'referrer-policy' => ['no-referrer'],
            ...$more,
        ];

        ksort($headers);

        return $headers;
    }

    /**
     * A completed result, delivered as given.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery  $delivery
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private static function completed(HandoffDelivery $delivery): CompletionResult
    {
        $handoff = new IssuedHandoff(HandoffCode::fromString(self::CODE), CarbonImmutable::parse('2026-11-01T10:01:00Z'));

        return CompletionResult::completed('https://app.example.com/sso', $delivery, RequestReference::fromString(self::REFERENCE), $handoff);
    }

    /**
     * The responses, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Responses\CompletionResponses
     */
    private function responses(): CompletionResponses
    {
        /** @var \SineMacula\Laravel\Sso\Responses\CompletionResponses */
        return $this->app?->make(CompletionResponses::class);
    }

    /**
     * The application's translator.
     *
     * @return \Illuminate\Translation\Translator
     */
    private function translator(): Translator
    {
        /** @var \Illuminate\Translation\Translator */
        return $this->app?->make('translator');
    }
}
