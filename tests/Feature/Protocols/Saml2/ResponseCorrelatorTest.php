<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\ResponseCorrelator;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for reading which request a SAML response answers (SSO-5.3,
 * SSO-5.8), validating nothing: HTTP-POST only, with a non-empty string
 * `SAMLResponse`; an unreadable envelope uncorrelated; no `InResponseTo`
 * anywhere unsolicited; `InResponseTo` values that disagree, or an id that is
 * empty or too long, uncorrelated; and otherwise solicited by the one id, with
 * a `RelayState` of at most 80 bytes as its state, and none otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResponseCorrelator::class)]
final class ResponseCorrelatorTest extends TestCase
{
    /** @var string The request the responses answer. */
    private const string REQUEST_ID = '_request-1';

    /** @var string The `RelayState` posted with them. */
    private const string RELAY_STATE = 'the-relay-state-of-the-correlated-request-01';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /**
     * A response answering a request, posted with its `RelayState`, is
     * solicited by the request's id, with the state's digest.
     *
     * @return void
     */
    public function testASolicitedResponseNamesItsRequestAndState(): void
    {
        $correlation = $this->correlate(self::response()->completionRequest(self::RELAY_STATE));

        self::assertSame(
            [CorrelationKind::SOLICITED, self::REQUEST_ID, hash('sha256', self::RELAY_STATE)],
            [$correlation->kind, $correlation->samlRequestId, $correlation->stateDigest()],
        );
    }

    /**
     * An id named only by a bearer confirmation, or only by the response,
     * correlates the response too.
     *
     * @return void
     */
    public function testAnInResponseToAnywhereCorrelates(): void
    {
        $confirmation = self::response()->with(['in_response_to' => null]);
        $envelope     = self::response()->inResponseTo(null)->with(['in_response_to' => self::REQUEST_ID]);

        self::assertSame(self::REQUEST_ID, $this->correlate($confirmation->completionRequest(self::RELAY_STATE))->samlRequestId);
        self::assertSame(self::REQUEST_ID, $this->correlate($envelope->completionRequest(self::RELAY_STATE))->samlRequestId);
    }

    /**
     * A response with no `InResponseTo` anywhere is unsolicited, whatever
     * `RelayState` it carries.
     *
     * @return void
     */
    public function testAResponseAnsweringNoRequestIsUnsolicited(): void
    {
        $correlation = $this->correlate(self::idp()->response('https://sp.example.test/m', 'https://sp.example.test/acs')->completionRequest(self::RELAY_STATE));

        self::assertSame([CorrelationKind::UNSOLICITED, null, null], [$correlation->kind, $correlation->samlRequestId, $correlation->stateDigest()]);
    }

    /**
     * `InResponseTo` values that disagree leave the response uncorrelated,
     * never unsolicited.
     *
     * @return void
     */
    public function testDisagreeingInResponseToValuesAreUncorrelated(): void
    {
        $correlation = $this->correlate(self::response()->with(['in_response_to' => '_request-2'])->completionRequest(self::RELAY_STATE));

        self::assertSame(CorrelationKind::UNCORRELATED, $correlation->kind);
    }

    /**
     * Rows of `[id, kind]`: the one id every `InResponseTo` names, and how the
     * response correlates.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind}>
     */
    public static function provideRequestIds(): iterable
    {
        yield from [
            'an empty id'        => ['', CorrelationKind::UNCORRELATED],
            'an id of one byte'  => ['_', CorrelationKind::SOLICITED],
            'an id of 255 bytes' => ['_' . str_repeat('a', 254), CorrelationKind::SOLICITED],
            'an id of 256 bytes' => ['_' . str_repeat('a', 255), CorrelationKind::UNCORRELATED],
            'an id of 254 bytes' => ['_' . str_repeat('a', 253), CorrelationKind::SOLICITED],
        ];
    }

    /**
     * An id that is empty or longer than a stored request id names no request.
     *
     * @param  string  $requestId
     * @param  \SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind  $kind
     * @return void
     */
    #[DataProvider('provideRequestIds')]
    public function testAnIdMustBeOneARequestCanCarry(string $requestId, CorrelationKind $kind): void
    {
        $correlation = $this->correlate(self::response()->inResponseTo($requestId)->completionRequest(self::RELAY_STATE));

        self::assertSame([$kind, $kind === CorrelationKind::SOLICITED ? $requestId : null], [$correlation->kind, $correlation->samlRequestId]);
    }

    /**
     * Rows of `[relayState, digest]`: the posted `RelayState`, and the state's
     * digest it correlates with.
     *
     * @return iterable<string, array{0: mixed, 1: ?string}>
     */
    public static function provideRelayStates(): iterable
    {
        yield from [
            '80 bytes'          => [str_repeat('r', 80), hash('sha256', str_repeat('r', 80))],
            '79 bytes'          => [str_repeat('r', 79), hash('sha256', str_repeat('r', 79))],
            '81 bytes'          => [str_repeat('r', 81), null],
            '80 bytes of UTF-8' => [str_repeat('é', 40), hash('sha256', str_repeat('é', 40))],
            '82 bytes of UTF-8' => [str_repeat('é', 41), null],
            'empty'             => ['', null],
            'an array'          => [[self::RELAY_STATE], null],
            'a number'          => [42, null],
        ];
    }

    /**
     * Only a `RelayState` that is a string of at most 80 bytes is carried; any
     * other leaves the response solicited by its id alone, so the consumed
     * request refuses it.
     *
     * @param  mixed  $relayState
     * @param  ?string  $digest
     * @return void
     */
    #[DataProvider('provideRelayStates')]
    public function testCarriesOnlyARelayStateOfAtMost80Bytes(mixed $relayState, ?string $digest): void
    {
        $request     = new CompletionRequest('POST', '', ['SAMLResponse' => self::response()->encoded(), 'RelayState' => $relayState]);
        $correlation = $this->correlate($request);

        self::assertSame([CorrelationKind::SOLICITED, self::REQUEST_ID, $digest], [$correlation->kind, $correlation->samlRequestId, $correlation->stateDigest()]);
    }

    /**
     * A response posted without a `RelayState` is solicited by its id alone.
     *
     * @return void
     */
    public function testAResponseWithoutRelayStateIsSolicitedByItsIdAlone(): void
    {
        $correlation = $this->correlate(self::response()->completionRequest());

        self::assertSame([CorrelationKind::SOLICITED, self::REQUEST_ID, null], [$correlation->kind, $correlation->samlRequestId, $correlation->stateDigest()]);
    }

    /**
     * Rows of `[request]`: what arrived, with no response the correlator reads.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Sso\Protocols\CompletionRequest}>
     */
    public static function provideUnread(): iterable
    {
        yield from [
            'a GET'                       => [static fn (): CompletionRequest => new CompletionRequest('GET', 'SAMLResponse=x', ['SAMLResponse' => self::response()->encoded()])],
            'a lower-case post'           => [static fn (): CompletionRequest => new CompletionRequest('post', '', ['SAMLResponse' => self::response()->encoded()])],
            'no SAMLResponse'             => [static fn (): CompletionRequest => new CompletionRequest('POST', '', ['RelayState' => self::RELAY_STATE])],
            'an empty SAMLResponse'       => [static fn (): CompletionRequest => new CompletionRequest('POST', '', ['SAMLResponse' => ''])],
            'an array SAMLResponse'       => [static fn (): CompletionRequest => new CompletionRequest('POST', '', ['SAMLResponse' => [self::response()->encoded()]])],
            'a numeric SAMLResponse'      => [static fn (): CompletionRequest => new CompletionRequest('POST', '', ['SAMLResponse' => 42])],
            'a SAMLResponse not base64'   => [static fn (): CompletionRequest => new CompletionRequest('POST', '', ['SAMLResponse' => '!!not base64!!'])],
            'a SAMLResponse not XML'      => [static fn (): CompletionRequest => new CompletionRequest('POST', '', ['SAMLResponse' => base64_encode('not xml')])],
            'a deflated SAMLResponse'     => [static fn (): CompletionRequest => new CompletionRequest('POST', '', ['SAMLResponse' => self::deflated()])],
            'a SAMLResponse over the cap' => [static fn (): CompletionRequest => new CompletionRequest('POST', '', [
                'SAMLResponse' => str_pad(self::response()->encoded(), Saml2Limits::DEFAULT_MAX_RESPONSE_BYTES + 1, "\n"),
            ])],
        ];
    }

    /**
     * Nothing is read from a request that is not an HTTP-POST carrying a
     * readable `SAMLResponse` string: it is uncorrelated.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return void
     */
    #[DataProvider('provideUnread')]
    public function testAResponseItCannotReadIsUncorrelated(\Closure $request): void
    {
        $correlation = $this->correlate($request());

        self::assertSame([CorrelationKind::UNCORRELATED, null, null], [$correlation->kind, $correlation->samlRequestId, $correlation->stateDigest()]);
    }

    /**
     * An encrypted assertion's `InResponseTo` cannot be seen: the response's
     * own correlates it, and one that names none is unsolicited until it is
     * validated.
     *
     * @return void
     */
    public function testAnEncryptedResponseIsCorrelatedByWhatItShows(): void
    {
        [, $certificate] = FakeSamlIdentityProvider::keyPair('sp.example.test');

        $named   = self::response()->encryptedFor($certificate);
        $unnamed = $named->with(['in_response_to' => null]);

        self::assertSame(self::REQUEST_ID, $this->correlate($named->completionRequest(self::RELAY_STATE))->samlRequestId);
        self::assertSame(CorrelationKind::UNSOLICITED, $this->correlate($unnamed->completionRequest(self::RELAY_STATE))->kind);
    }

    /**
     * What the correlator reads of the request, for any connection.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     */
    private function correlate(CompletionRequest $request): Correlation
    {
        return app(ResponseCorrelator::class)->correlate(new ExampleConnection('saml2'), $request);
    }

    /**
     * A valid response answering the request.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function response(): FakeSamlResponse
    {
        return self::idp()->response('https://sp.example.test/m', 'https://sp.example.test/acs')->inResponseTo(self::REQUEST_ID);
    }

    /**
     * The response deflated, as the HTTP-Redirect binding carries a message,
     * then encoded.
     *
     * @return string
     */
    private static function deflated(): string
    {
        return base64_encode((string) gzdeflate(self::response()->toXml()));
    }

    /**
     * The identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
