<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Results\ExampleResults;
use Tests\TestCase;

/**
 * Feature tests for what a completion has established: each part added by its
 * own `with…()` with every other kept, a redirect target only once the request,
 * its application and the connection are known, a dump showing only ids, no
 * serialisation; and what a stage decided.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionState::class)]
#[CoversClass(StageOutcome::class)]
final class CompletionStateTest extends TestCase
{
    /**
     * A completion that has just arrived holds the connection id and what
     * arrived, and nothing else.
     *
     * @return void
     */
    public function testAnArrivedCompletionHoldsOnlyWhatArrived(): void
    {
        $request = new CompletionRequest('POST', '', ['SAMLResponse' => 'x']);
        $state   = CompletionState::arrived('01jbexampleconnection00000', $request);

        self::assertSame('01jbexampleconnection00000', $state->connectionId);
        self::assertSame($request, $state->request);

        $parts = [
            'connection', 'correlation', 'authorizationRequest', 'consumed', 'application', 'enforcementPolicy', 'claims', 'result', 'linkedIdentity',
            'sessionNotAfter', 'handoff',
        ];

        foreach ($parts as $part) {
            self::assertNull($state->{$part}, $part);
        }

        self::assertFalse($state->hasRedirectTarget());
    }

    /**
     * Each `with…()` adds its part to a new state and keeps every other.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachPartIsAddedAndTheRestKept(): void
    {
        $connection  = new Connection;
        $correlation = Correlation::solicited('state-1');
        $request     = new AuthorizationRequest;
        $consumed    = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(str_repeat('r', 32)), CarbonImmutable::now());
        $application = Application::fromSettings('web', ['redirect_uri' => 'https://app.example.com/sso']);
        $claims      = ExampleResults::claims();
        $result      = ExampleResults::full();
        $identity    = new IdentityReference('user', '1');
        $notAfter    = CarbonImmutable::parse('2026-11-01T18:00:00Z');
        $handoff     = new IssuedHandoff(HandoffCode::generate(), CarbonImmutable::now());
        $policy      = EnforcementPolicy::required('tenant-1', 'tenant-1', ['c'], 'version-1');

        $first = CompletionState::arrived('c', new CompletionRequest('GET', 'state=1', []));
        $state = $first->withConnection($connection)
            ->withCorrelation($correlation)
            ->withAuthorizationRequest($request, $consumed, $application)
            ->withEnforcementPolicy($policy)
            ->withClaims($claims)
            ->withResult($result)
            ->withResolution(ExampleLinks::resolution($identity))
            ->withSessionNotAfter($notAfter)
            ->withHandoff($handoff);

        self::assertNull($first->connection);
        self::assertSame('c', $state->connectionId);
        self::assertSame($first->request, $state->request);
        self::assertSame($connection, $state->connection);
        self::assertSame($correlation, $state->correlation);
        self::assertSame($request, $state->authorizationRequest);
        self::assertSame($consumed, $state->consumed);
        self::assertSame($application, $state->application);
        self::assertSame($policy, $state->enforcementPolicy);
        self::assertSame($claims, $state->claims);
        self::assertSame($result, $state->result);
        self::assertSame($identity, $state->linkedIdentity);
        self::assertSame($notAfter, $state->sessionNotAfter);
        self::assertSame($handoff, $state->handoff);
        self::assertTrue($state->hasRedirectTarget());
    }

    /**
     * A redirect target is known only once the request, its application and the
     * connection all are.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedirectTargetNeedsTheRequestItsApplicationAndTheConnection(): void
    {
        $consumed    = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::generate(), CarbonImmutable::now());
        $application = Application::fromSettings('web', ['redirect_uri' => 'https://app.example.com/sso']);
        $arrived     = CompletionState::arrived('c', new CompletionRequest('GET', '', []));

        self::assertFalse($arrived->withConnection(new Connection)->hasRedirectTarget());
        self::assertFalse($arrived->withAuthorizationRequest(new AuthorizationRequest, $consumed, $application)->hasRedirectTarget());
        self::assertTrue($arrived->withConnection(new Connection)->withAuthorizationRequest(new AuthorizationRequest, $consumed, $application)->hasRedirectTarget());
    }

    /**
     * A dump shows ids and which parts are set, never what arrived or the code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testADumpShowsOnlyIds(): void
    {
        $arrived = CompletionState::arrived('c', new CompletionRequest('POST', '', ['SAMLResponse' => 'secret-response']));

        self::assertSame([
            'connection_id'     => 'c',
            'request_reference' => null,
            'application'       => null,
            'verified'          => false,
            'linked'            => false,
            'handed_off'        => false,
            'resolution'        => null,
            'reserved'          => false,
        ], $arrived->__debugInfo());

        $code  = HandoffCode::generate();
        $state = $arrived
            ->withAuthorizationRequest(
                new AuthorizationRequest,
                new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(str_repeat('r', 32)), CarbonImmutable::now()),
                Application::fromSettings('web', ['redirect_uri' => 'https://app.example.com/sso']),
            )
            ->withResult(ExampleResults::full())
            ->withResolution(ExampleLinks::resolution(new IdentityReference('user', '1')))
            ->withHandoff(new IssuedHandoff($code, CarbonImmutable::now()));

        self::assertSame([
            'connection_id'     => 'c',
            'request_reference' => str_repeat('r', 32),
            'application'       => 'web',
            'verified'          => true,
            'linked'            => true,
            'handed_off'        => true,
            'resolution'        => 'linked',
            'reserved'          => false,
        ], $state->__debugInfo());
        self::assertStringNotContainsString('secret-response', print_r($state, true));
        self::assertStringNotContainsString($code->reveal(), print_r($state, true));
    }

    /**
     * A state cannot be serialised.
     *
     * @return void
     */
    public function testCannotBeSerialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A completion\'s state cannot be serialised.'));

        serialize(CompletionState::arrived('c', new CompletionRequest('GET', '', [])));
    }

    /**
     * A state cannot be unserialised.
     *
     * @return void
     */
    public function testCannotBeUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A completion\'s state cannot be unserialised.'));

        unserialize('O:49:"SineMacula\Laravel\Sso\Completion\CompletionState":0:{}');
    }

    /**
     * A stage proceeds with its state, or refuses with its state and a reason.
     *
     * @return void
     */
    public function testWhatAStageDecided(): void
    {
        $state   = CompletionState::arrived('c', new CompletionRequest('GET', '', []));
        $proceed = StageOutcome::proceed($state);
        $refuse  = StageOutcome::refuse($state, FailureReason::ENFORCEMENT_UNSATISFIED);

        self::assertTrue($proceed->isProceeding());
        self::assertFalse($proceed->isRefused());
        self::assertSame($state, $proceed->state);
        self::assertNull($proceed->reason);
        self::assertTrue($refuse->isRefused());
        self::assertFalse($refuse->isProceeding());
        self::assertSame($state, $refuse->state);
        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $refuse->reason);
    }
}
