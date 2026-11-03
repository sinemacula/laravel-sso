<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for the unlinked-result event (SSO-8.6, SSO-10.5): a listener
 * reads the exact result and the grant, and nothing else shows them; it refuses
 * to be serialised, so a queued listener fails loudly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResultUnlinked::class)]
final class ResultUnlinkedTest extends TestCase
{
    use DumpsValues;

    /** @var string The subject the result carries. */
    private const string SUBJECT = 'the-subject-of-the-result';

    /** @var string The attribute the result carries. */
    private const string ATTRIBUTE = 'attribute-of-the-result';

    /** @var string The issuer the result carries. */
    private const string ISSUER = 'https://idp.example.com/of-the-result';

    /**
     * A listener reads the event's context, the exact result and the grant.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAListenerReadsWhatItCarries(): void
    {
        [$event, $context, $result, $grant] = self::event();

        self::assertInstanceOf(SsoEvent::class, $event);
        self::assertSame($context, $event->context);
        self::assertSame($context, $event->context());
        self::assertSame($result, $event->result);
        self::assertSame($grant, $event->grant);
    }

    /**
     * Only `result` is read magically, and only it is set.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOnlyTheResultIsReadThisWay(): void
    {
        [$event] = self::event();

        self::assertTrue(isset($event->result));
        self::assertFalse(isset($event->subject)); // @phpstan-ignore property.notFound

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The unlinked-result event has no [subject].');

        $event->subject; // @phpstan-ignore expr.resultUnused, property.notFound
    }

    /**
     * A dump shows the context with the rest redacted, and `json_encode()` the
     * context alone.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testADumpAndJsonShowOnlyItsContext(): void
    {
        [$event, $context] = self::event();

        self::assertSame(['context' => $context, 'result' => '[redacted]', 'grant' => '[redacted]'], $event->__debugInfo());
        self::assertSame(['context' => $context->toArray()], $event->jsonSerialize());
        self::assertSame((string) json_encode(['context' => $context->toArray()]), json_encode($event));
    }

    /**
     * No dump, export or array cast shows the result.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNothingShowsTheResult(): void
    {
        [$event] = self::event();

        foreach ([...self::dumps($event), 'array cast' => print_r((array) $event, true), 'array cast export' => var_export((array) $event, true)] as $how => $dump) {
            foreach ([self::SUBJECT, self::ATTRIBUTE, self::ISSUER] as $secret) {
                self::assertStringNotContainsString($secret, $dump, $how);
            }
        }
    }

    /**
     * A clone, which a queue makes before it serialises, shares the one grant
     * and the exact result: it is no second use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACloneSharesTheGrantAndTheResult(): void
    {
        [$event, , $result, $grant] = self::event();

        $copy = clone $event;

        self::assertSame($grant, $copy->grant);
        self::assertSame($result, $copy->result);
    }

    /**
     * It refuses to be serialised: a queued listener is too late.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testItCannotBeSerialised(): void
    {
        [$event] = self::event();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The unlinked-result event cannot be serialised: a queued listener is too late (SSO-8.6).');

        serialize($event);
    }

    /**
     * It refuses to be unserialised.
     *
     * @return void
     */
    public function testItCannotBeUnserialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The unlinked-result event cannot be unserialised.');

        unserialize('O:' . strlen(ResultUnlinked::class) . ':"' . ResultUnlinked::class . '":0:{}');
    }

    /**
     * An event, with what it was made from.
     *
     * @return array{
     *     0: \SineMacula\Laravel\Sso\Events\ResultUnlinked,
     *     1: \SineMacula\Laravel\Sso\Events\EventContext,
     *     2: \SineMacula\Laravel\Sso\Results\VerifiedResult,
     *     3: \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant,
     * }
     *
     * @throws \Random\RandomException
     */
    private static function event(): array
    {
        $now     = CarbonImmutable::parse('2026-11-01T09:30:00Z');
        $context = new EventContext($now, connectionId: 'connection-1', connectionTenantId: 'tenant-1', protocol: 'oidc', application: 'web', purpose: 'sign_in');
        $result  = new VerifiedResult(
            self::ISSUER,
            self::SUBJECT,
            null,
            'connection-1',
            'tenant-1',
            'oidc',
            'web',
            Purpose::SIGN_IN,
            RequestReference::generate(),
            ['name' => self::ATTRIBUTE],
            false,
            new AuthenticationContext,
        );
        $grant = ProvisioningGrant::issue($result, '01jbexamplerequest00000001', $now->addMinutes(2));

        return [new ResultUnlinked($context, $result, $grant), $context, $result, $grant];
    }
}
