<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Navigations;
use SineMacula\Laravel\Sso\Testing\Saml\FakeAuthnRequest;

/**
 * Unit tests for the fake identity providers reading a start's request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSamlIdentityProvider::class)]
#[CoversClass(FakeOpenIdProvider::class)]
#[CoversClass(Navigations::class)]
final class FakeProvidersReadTheStartTest extends TestCase
{
    /** @var string The service provider's assertion consumer service. */
    private const string ACS = 'https://sp.example.test/acs';

    /** @var string The service provider's entity id. */
    private const string SP = 'https://sp.example.test/metadata';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The SAML provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /**
     * Clear any time a test froze.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The SAML provider receives the request the start's navigation carries.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSamlProviderReceivesTheRequest(): void
    {
        $request = self::idp()->receive(self::started(false));

        self::assertSame(
            ['_request-1', self::SP, self::ACS, 'relay-1', false],
            [$request->id, $request->issuer, $request->assertionConsumerService, $request->relayState, $request->forceAuthn],
        );
    }

    /**
     * The response answers the request's `ID`, issuer and assertion consumer
     * service at the instant given, authenticated a minute before.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSamlProviderAnswersTheRequest(): void
    {
        $now      = CarbonImmutable::parse('2026-11-01T09:30:00Z');
        $response = self::idp()->respondTo(self::idp()->receive(self::started(false)), $now);

        /** @var list<array{recipient: ?string, in_response_to: ?string}> $confirmations */
        $confirmations = $response->option('confirmations');

        /** @var list<array{instant: \Carbon\CarbonImmutable}> $statements */
        $statements = $response->option('authn_statements');

        self::assertSame(
            ['_request-1', self::ACS, [[self::SP]], self::ACS, '_request-1', '2026-11-01T09:30:00Z', '2026-11-01T09:29:00Z'],
            [
                $response->option('in_response_to'),
                $response->option('destination'),
                $response->option('audiences'),
                $confirmations[0]['recipient'],
                $confirmations[0]['in_response_to'],
                self::instant($response->option('issue_instant')),
                self::instant($statements[0]['instant']),
            ],
        );
    }

    /**
     * A forced authentication is made at the instant given, and a response with
     * no instant is made now.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSamlProviderAuthenticatesAgainWhenForced(): void
    {
        CarbonImmutable::setTestNow('2026-11-02T10:00:00Z');

        $forced   = self::idp()->receive(self::started(true));
        $response = self::idp()->respondTo($forced, CarbonImmutable::parse('2026-11-01T09:30:00Z'));
        $current  = self::idp()->respondTo($forced);

        /** @var list<array{instant: \Carbon\CarbonImmutable, session_index: ?string}> $statements */
        $statements = $response->option('authn_statements');

        /** @var list<array{instant: \Carbon\CarbonImmutable}> $now */
        $now = $current->option('authn_statements');

        self::assertCount(1, $statements);
        self::assertSame('2026-11-01T09:30:00Z', self::instant($statements[0]['instant']));
        self::assertNotNull($statements[0]['session_index']);
        self::assertSame(['2026-11-02T10:00:00Z', '2026-11-02T10:00:00Z'], [self::instant($current->option('issue_instant')), self::instant($now[0]['instant'])]);
    }

    /**
     * The OpenID provider grants the request whether given the start's result,
     * its navigation or its URL.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheOpenIdProviderGrantsTheRequestInEachForm(): void
    {
        $provider   = new FakeOpenIdProvider;
        $navigation = Navigation::redirect($provider->endpoint('authorization') . '?state=st&nonce=no');
        $started    = StartResult::started(RequestReference::generate(), $navigation);

        foreach ([$started, $navigation, $navigation->url()] as $given) {

            $grant = $provider->authorize($given);

            self::assertSame(['st', 'no'], [$grant->parameter('state'), $grant->parameter('nonce')]);
        }
    }

    /**
     * Neither provider reads a start that was refused or rate limited, and each
     * says why.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNeitherReadsAStartThatWasRefused(): void
    {
        $messages = [];

        $attempts = [
            static fn (): mixed => self::idp()->receive(StartResult::refused(FailureReason::FRESHNESS_REQUIRED)),
            static fn (): mixed => (new FakeOpenIdProvider)->authorize(StartResult::rateLimited(30)),
        ];

        foreach ($attempts as $attempt) {
            try {
                $attempt();
            } catch (\LogicException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        self::assertSame([
            'The flow did not start: it was refused with [freshness_required].',
            'The flow did not start: it was refused with [rate_limited].',
        ], $messages);
    }

    /**
     * A started flow whose navigation posts an `AuthnRequest` of the service
     * provider, forcing authentication or not.
     *
     * @param  bool  $forced
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     *
     * @throws \Random\RandomException
     */
    private static function started(bool $forced): StartResult
    {
        $xml = sprintf(
            '<samlp:AuthnRequest xmlns:samlp="%s" xmlns:saml="%s" ID="_request-1" AssertionConsumerServiceURL="%s"%s><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>',
            FakeAuthnRequest::NS_SAMLP,
            FakeAuthnRequest::NS_SAML,
            self::ACS,
            $forced ? ' ForceAuthn="true"' : '',
            self::SP,
        );

        $fields = ['SAMLRequest' => base64_encode($xml), 'RelayState' => 'relay-1'];

        return StartResult::started(RequestReference::generate(), Navigation::post(FakeSamlIdentityProvider::SSO_URL, $fields));
    }

    /**
     * An instant as an option holds it, in UTC.
     *
     * @param  mixed  $instant
     * @return string
     */
    private static function instant(mixed $instant): string
    {
        self::assertInstanceOf(CarbonImmutable::class, $instant);

        return $instant->utc()->format('Y-m-d\TH:i:s\Z');
    }

    /**
     * The SAML provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
