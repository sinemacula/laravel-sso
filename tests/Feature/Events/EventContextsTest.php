<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Http\ClientContext;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the one projection that builds an event's context: the time
 * from the package's clock, the client from the client context each call is
 * given, never from the request being served, and each field cleaned and
 * capped, with the client context and strings the only input it admits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContexts::class)]
final class EventContextsTest extends TestCase
{
    /** @var \Tests\Fixtures\FixedClock The clock the projection reads. */
    private FixedClock $clock;

    /**
     * Bind the fixed clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-10-31T12:00:00.123456Z');

        $this->app?->instance(Clock::class, $this->clock);
    }

    /**
     * The time of the context is the bound clock's, read when it is built.
     *
     * @return void
     */
    public function testTheTimeComesFromTheBoundClock(): void
    {
        $contexts = $this->contexts();

        self::assertSame('2026-10-31T12:00:00.123456Z', $contexts->make(Clients::browser())->toArray()['occurred_at']);

        $this->clock->advance(90);

        self::assertSame('2026-10-31T12:01:30.123456Z', $contexts->make(Clients::browser())->toArray()['occurred_at']);
    }

    /**
     * The client comes from the context given: its IP address, and its user
     * agent as the context cleaned it: control characters (C0, DEL, C1),
     * bidirectional controls and invalid UTF-8 are removed before the cut, so
     * all 512 characters kept are ones that survived.
     *
     * @return void
     */
    public function testTheClientComesFromItsContextCleaned(): void
    {
        $userAgent = "Mozilla/5.0\x00\x1b\u{0085}\x7F (X11\u{202A}\u{202E}\u{2066}\u{2069}; \xFF)" . str_repeat('a', 600);

        $context = $this->contexts()->make(new ClientContext('203.0.113.7', $userAgent));

        self::assertSame('203.0.113.7', $context->ip);
        self::assertSame('Mozilla/5.0 (X11; ?)' . str_repeat('a', 492), $context->userAgent);
    }

    /**
     * A user agent the client context keeps whole keeps its length here too:
     * 512 characters, none of them removed.
     *
     * @return void
     */
    public function testAUserAgentAtItsCapIsKeptWhole(): void
    {
        $userAgent = str_repeat('é', EventContexts::USER_AGENT_MAX_LENGTH);

        self::assertSame($userAgent, $this->contexts()->make(new ClientContext('203.0.113.7', $userAgent))->userAgent);
    }

    /**
     * An IPv6 address is kept as the context gives it.
     *
     * @return void
     */
    public function testAnIpv6AddressIsKept(): void
    {
        self::assertSame('2001:db8::1', $this->contexts()->make(new ClientContext('2001:db8::1', 'Example/1.0'))->ip);
    }

    /**
     * An address that is not a valid IPv4 or IPv6 address is not kept, and a
     * user agent that is empty once cleaned, or not sent, is none.
     *
     * @return void
     */
    public function testAnInvalidAddressAndAnEmptyUserAgentAreNone(): void
    {
        $context = $this->contexts()->make(new ClientContext('not-an-address', "\x00\u{202E}\x1f"));

        self::assertNull($context->ip);
        self::assertNull($context->userAgent);
        self::assertNull($this->contexts()->make(new ClientContext('203.0.113.7', null))->userAgent);
    }

    /**
     * Work with no client gives none: the context of background work holds no
     * IP address and no user agent.
     *
     * @return void
     */
    public function testNoClientGivesNoClient(): void
    {
        $context = $this->contexts()->make(new ClientContext(null, null), connectionId: 'conn_1');

        self::assertNull($context->ip);
        self::assertNull($context->userAgent);
        self::assertSame('conn_1', $context->connectionId);
    }

    /**
     * The request being served is never read: a context built while one is
     * bound holds the client given, and one built with no request bound at all
     * holds it too.
     *
     * @return void
     */
    public function testTheRequestBeingServedIsNeverRead(): void
    {
        $this->serve('198.51.100.9', 'Served/1.0');

        $context = $this->contexts()->make(new ClientContext('203.0.113.7', 'Given/1.0'));

        self::assertSame(['203.0.113.7', 'Given/1.0'], [$context->ip, $context->userAgent]);

        /** @var \Illuminate\Foundation\Application $app */
        $app     = $this->app;
        $request = $app->make('request');

        $app->offsetUnset('request');

        try {
            $context = $this->contexts()->make(new ClientContext('203.0.113.7', 'Given/1.0'));

            self::assertSame(['203.0.113.7', 'Given/1.0'], [$context->ip, $context->userAgent]);
        } finally {
            $app->instance('request', $request);
        }
    }

    /**
     * Every field named reaches the context, under its own name.
     *
     * @return void
     */
    public function testEveryNamedFieldReachesTheContext(): void
    {
        $context = $this->contexts()->make(
            new ClientContext('203.0.113.7', 'Example/1.0'),
            connectionId: 'conn_1',
            connectionTenantId: 'tenant_1',
            protocol: 'saml2',
            application: 'web',
            purpose: 'sign_in',
            requestReference: 'ref_1',
            identityMorphClass: 'user',
            identityId: '42',
            actingIdentityMorphClass: 'admin',
            actingIdentityId: '7',
            principalMorphClass: 'membership',
            principalId: '9',
            tenantId: 'tenant_2',
            sessionId: 'session_1',
            method: 'sso',
        );

        self::assertSame([
            'occurred_at'                 => '2026-10-31T12:00:00.123456Z',
            'ip'                          => '203.0.113.7',
            'user_agent'                  => 'Example/1.0',
            'connection_id'               => 'conn_1',
            'connection_tenant_id'        => 'tenant_1',
            'protocol'                    => 'saml2',
            'application'                 => 'web',
            'purpose'                     => 'sign_in',
            'request_reference'           => 'ref_1',
            'identity_morph_class'        => 'user',
            'identity_id'                 => '42',
            'acting_identity_morph_class' => 'admin',
            'acting_identity_id'          => '7',
            'principal_morph_class'       => 'membership',
            'principal_id'                => '9',
            'tenant_id'                   => 'tenant_2',
            'session_id'                  => 'session_1',
            'method'                      => 'sso',
        ], $context->toArray());
    }

    /**
     * A field not given is none.
     *
     * @return void
     */
    public function testAFieldNotGivenIsNone(): void
    {
        $context = $this->contexts()->make(Clients::browser(), connectionId: 'conn_1');

        $fields = $context->toArray();

        unset($fields['occurred_at'], $fields['ip'], $fields['user_agent'], $fields['connection_id']);

        self::assertSame([null], array_values(array_unique($fields, SORT_REGULAR)));
    }

    /**
     * Each named field has its control and bidirectional characters removed,
     * invalid UTF-8 replaced, and is cut to 255 characters, so an id can never
     * smuggle a payload; one that is empty once cleaned is none.
     *
     * @return void
     */
    public function testEachFieldIsCleanedAndCapped(): void
    {
        $context = $this->contexts()->make(
            Clients::browser(),
            connectionId: "conn\x00\x1f\u{0085}" . str_repeat('x', 300),
            connectionTenantId: "tenant\r\n_1\u{202E}",
            requestReference: "ref\xC3",
            method: "\x00\x7F",
        );

        self::assertSame('conn' . str_repeat('x', 251), $context->connectionId);
        self::assertSame(EventContexts::FIELD_MAX_LENGTH, mb_strlen($context->connectionId));
        self::assertSame('tenant_1', $context->connectionTenantId);
        self::assertSame('ref?', $context->requestReference);
        self::assertNull($context->method);
    }

    /**
     * Each call takes its own client, and the projection holds none: one
     * projection reports each call's client.
     *
     * @return void
     */
    public function testEachCallTakesItsOwnClient(): void
    {
        $contexts = $this->contexts();

        $first  = $contexts->make(new ClientContext('203.0.113.7', 'First/1.0'));
        $second = $contexts->make(new ClientContext('198.51.100.9', 'Second/2.0'));

        self::assertSame(['203.0.113.7', 'First/1.0'], [$first->ip, $first->userAgent]);
        self::assertSame(['198.51.100.9', 'Second/2.0'], [$second->ip, $second->userAgent]);
    }

    /**
     * The parameter list is the admission control: the client context first,
     * required, then every other parameter a nullable string, defaulting to
     * none, and together they are the context's fields but its time and client,
     * in the context's order. No array or other object can be passed, so a
     * verified result never reaches an event whole.
     *
     * @return void
     */
    public function testTheProjectionAdmitsTheClientAndStringFields(): void
    {
        $parameters = (new \ReflectionMethod(EventContexts::class, 'make'))->getParameters();
        $client     = array_shift($parameters);

        self::assertNotNull($client);
        self::assertSame(['client', ClientContext::class, false], [$client->getName(), (string) $client->getType(), $client->isOptional()]);

        $fields = array_map(
            static fn (\ReflectionParameter $parameter): string => $parameter->getName(),
            (new \ReflectionMethod(EventContext::class, '__construct'))->getParameters(),
        );

        self::assertSame(
            array_values(array_diff($fields, ['occurredAt', 'ip', 'userAgent'])),
            array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $parameters),
        );

        foreach ($parameters as $parameter) {
            self::assertSame('?string', (string) $parameter->getType(), "{$parameter->getName()} admits more than a string.");
            self::assertTrue($parameter->isDefaultValueAvailable());
            self::assertNull($parameter->getDefaultValue());
        }
    }

    /**
     * Bind a request from the address with the user agent as the one being
     * served, which the projection must never read.
     *
     * @param  string  $ip
     * @param  string  $userAgent
     * @return void
     */
    private function serve(string $ip, string $userAgent): void
    {
        $this->app?->instance('request', Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR'     => $ip,
            'HTTP_USER_AGENT' => $userAgent,
        ]));
    }

    /**
     * Resolve the projection from the container, as the package does.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContexts
     */
    private function contexts(): EventContexts
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(EventContexts::class);
    }
}
