<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\EventContexts;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the one projection that builds an event's context: the time
 * from the package's clock, the client from the request being served, resolved
 * on each call, and each field cleaned and capped, with strings the only input
 * it admits.
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

        self::assertSame('2026-10-31T12:00:00.123456Z', $contexts->make()->toArray()['occurred_at']);

        $this->clock->advance(90);

        self::assertSame('2026-10-31T12:01:30.123456Z', $contexts->make()->toArray()['occurred_at']);
    }

    /**
     * The client comes from the request being served: its IP address, and its
     * user agent with control characters (C0, DEL, C1) and bidirectional
     * controls removed, invalid UTF-8 replaced, and cut to 512 characters.
     *
     * @return void
     */
    public function testTheClientComesFromTheRequestCleanedAndCapped(): void
    {
        $userAgent = "Mozilla/5.0\x00\x1b\u{0085}\x7F (X11\u{202A}\u{202E}\u{2066}\u{2069}; \xFF)" . str_repeat('a', 600);

        $this->serve('203.0.113.7', $userAgent);

        $context = $this->contexts()->make();

        self::assertSame('203.0.113.7', $context->ip);
        self::assertSame('Mozilla/5.0 (X11; ?)' . str_repeat('a', 492), $context->userAgent);
        self::assertSame(EventContexts::USER_AGENT_MAX_LENGTH, mb_strlen($context->userAgent));
    }

    /**
     * An IPv6 address is kept as the request gives it.
     *
     * @return void
     */
    public function testAnIpv6AddressIsKept(): void
    {
        $this->serve('2001:db8::1', 'Example/1.0');

        self::assertSame('2001:db8::1', $this->contexts()->make()->ip);
    }

    /**
     * An address that is not a valid IPv4 or IPv6 address is not kept, and a
     * user agent that is empty once cleaned, or not sent, is none.
     *
     * @return void
     */
    public function testAnInvalidAddressAndAnEmptyUserAgentAreNone(): void
    {
        $this->serve('not-an-address', "\x00\u{202E}\x1f");

        $context = $this->contexts()->make();

        self::assertNull($context->ip);
        self::assertNull($context->userAgent);

        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.7']);
        $request->headers->remove('User-Agent');

        $this->app?->instance('request', $request);

        self::assertNull($this->contexts()->make()->userAgent);
    }

    /**
     * In the console, with no client, the context holds what the request the
     * application bound for the console reports.
     *
     * @return void
     */
    public function testTheConsoleGivesTheRequestsOwnAddress(): void
    {
        /** @var \Illuminate\Http\Request $request */
        $request = $this->app?->make('request');

        $context = $this->contexts()->make();

        self::assertNotNull($context->ip);
        self::assertSame($request->ip(), $context->ip);
        self::assertSame($request->userAgent(), $context->userAgent);
    }

    /**
     * With no request bound at all, the context holds no client.
     *
     * @return void
     */
    public function testNoRequestBoundGivesNoClient(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app     = $this->app;
        $request = $app->make('request');

        $app->offsetUnset('request');

        try {
            self::assertFalse($app->bound('request'));

            $context = $this->contexts()->make(connectionId: 'conn_1');

            self::assertNull($context->ip);
            self::assertNull($context->userAgent);
            self::assertSame('conn_1', $context->connectionId);
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
        $this->serve('203.0.113.7', 'Example/1.0');

        $context = $this->contexts()->make(
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
        $context = $this->contexts()->make(connectionId: 'conn_1');

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
     * The request is resolved when the context is built, never held: one
     * projection rebound between two calls reports each call's client.
     *
     * @return void
     */
    public function testTheRequestIsResolvedOnEachCall(): void
    {
        $contexts = $this->contexts();

        $this->serve('203.0.113.7', 'First/1.0');

        $first = $contexts->make();

        $this->serve('198.51.100.9', 'Second/2.0');

        $second = $contexts->make();

        self::assertSame(['203.0.113.7', 'First/1.0'], [$first->ip, $first->userAgent]);
        self::assertSame(['198.51.100.9', 'Second/2.0'], [$second->ip, $second->userAgent]);
    }

    /**
     * The parameter list is the admission control: every parameter is a
     * nullable string, defaulting to none, and together they are the context's
     * fields but its time and client, in the context's order. No array or
     * object can be passed, so a verified result never reaches an event whole.
     *
     * @return void
     */
    public function testTheProjectionAdmitsTheContextsStringFieldsOnly(): void
    {
        $parameters = (new \ReflectionMethod(EventContexts::class, 'make'))->getParameters();

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
     * served.
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
