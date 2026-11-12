<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the administration change reporter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdministrationEvents::class)]
final class AdministrationEventsTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /**
     * Bind a fixed clock, create the tables, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->usePackageTables();
        $this->startRecordingEvents();
    }

    /**
     * Each connection change becomes its event with the connection and the
     * acting identity.
     *
     * @return void
     */
    public function testReportsEachConnectionChange(): void
    {
        $connection = $this->makeConnection(['tenant_id' => 'tenant-7', 'protocol' => 'saml2']);
        $actor      = new Caller(new IdentityReference('App\Models\User', '42'));

        $this->events()->connectionCreated($connection, $actor, Clients::browser());
        $this->events()->connectionUpdated($connection, ['sso_url', 'display_name', 'sso_url'], $actor, Clients::browser());
        $this->events()->connectionEnabled($connection, $actor, Clients::browser());
        $this->events()->connectionDisabled($connection, null, Clients::browser());
        $this->events()->connectionDeleted($connection, $actor, Clients::browser());

        $this->assertEventSequence([ConnectionCreated::class, ConnectionUpdated::class, ConnectionEnabled::class, ConnectionDisabled::class, ConnectionDeleted::class]);

        $events = $this->recordedEvents();

        foreach ($events as $index => $event) {

            $context = $event->context();

            self::assertSame($connection->id, $context->connectionId);
            self::assertSame('tenant-7', $context->connectionTenantId);
            self::assertSame('saml2', $context->protocol);
            self::assertSame($index === 3 ? null : 'App\Models\User', $context->actingIdentityMorphClass);
            self::assertSame($index === 3 ? null : '42', $context->actingIdentityId);
            self::assertNull($context->identityId);
            self::assertNull($context->requestReference);
        }

        self::assertInstanceOf(ConnectionUpdated::class, $events[1]);
        self::assertSame(['sso_url', 'display_name'], $events[1]->changedSettings);
    }

    /**
     * An update that changed nothing reports nothing.
     *
     * @return void
     */
    public function testAnUpdateThatChangedNothingReportsNothing(): void
    {
        $this->events()->connectionUpdated($this->makeConnection(), [], null, Clients::browser());

        $this->assertNoEvents();
    }

    /**
     * Each key change becomes its event, never carrying the private key.
     *
     * @return void
     */
    public function testReportsEachKeyChange(): void
    {
        $connection = $this->makeConnection();
        $previous   = $this->makeKey($connection, KeyState::RETIRING, str_repeat('a', 64));
        $key        = $this->makeKey($connection, KeyState::CURRENT, str_repeat('b', 64));

        $this->events()->keyAdded($connection, $key, null, Clients::browser());
        $this->events()->keyMadeCurrent($connection, $key, $previous, null, Clients::browser());
        $this->events()->keyMadeCurrent($connection, $key, null, null, Clients::browser());
        $this->events()->keyRetired($connection, $previous, null, Clients::browser());
        $this->events()->keyNearingExpiry($connection, $key, 14, Clients::browser());

        $this->assertEventSequence([KeyAdded::class, KeyMadeCurrent::class, KeyMadeCurrent::class, KeyRetired::class, KeyNearingExpiry::class]);

        [$added, $made, $first, $retired, $nearing] = $this->recordedEvents();

        self::assertInstanceOf(KeyAdded::class, $added);
        self::assertSame([$key->id, KeyUse::CLIENT_ASSERTION, KeyState::CURRENT, str_repeat('b', 64)], [$added->keyId, $added->use, $added->state, $added->fingerprint]);
        self::assertSame('2027-01-01T00:00:00Z', $added->notAfter?->format('Y-m-d\TH:i:s\Z'));
        self::assertInstanceOf(KeyMadeCurrent::class, $made);
        self::assertSame($previous->id, $made->previousKeyId);
        self::assertInstanceOf(KeyMadeCurrent::class, $first);
        self::assertNull($first->previousKeyId);
        self::assertInstanceOf(KeyRetired::class, $retired);
        self::assertSame($previous->id, $retired->keyId);
        self::assertInstanceOf(KeyNearingExpiry::class, $nearing);
        self::assertSame('2027-01-01T00:00:00Z', $nearing->notAfter->format('Y-m-d\TH:i:s\Z'));
        self::assertSame(14, $nearing->thresholdDays);

        foreach ($this->recordedEvents() as $event) {
            self::assertStringNotContainsString('encrypted-private-key', serialize($event));
        }
    }

    /**
     * A key with no end of validity is never reported as nearing expiry.
     *
     * @return void
     */
    public function testAKeyWithNoEndOfValidityIsNeverNearingExpiry(): void
    {
        $connection = $this->makeConnection();
        $key        = $this->makeKey($connection, KeyState::CURRENT, str_repeat('c', 64), false);

        $this->events()->keyNearingExpiry($connection, $key, 30, Clients::browser());

        $this->assertNoEvents();
    }

    /**
     * An event reaches listeners once the transaction commits, never on
     * rollback.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsOnlyOnceTheChangeCommits(): void
    {
        $connection = $this->makeConnection();

        DB::transaction(function () use ($connection): void {
            $this->events()->connectionEnabled($connection, null, Clients::browser());

            $this->assertNoEvents();
        });

        $this->assertEventSequence([ConnectionEnabled::class]);

        $this->startRecordingEvents();

        try {
            DB::transaction(function () use ($connection): void {
                $this->events()->connectionDisabled($connection, null, Clients::browser());

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException) {
            // The rollback is the point.
        }

        $this->assertNoEvents();
    }

    /**
     * Make and save a client assertion key of the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  string  $fingerprint
     * @param  bool  $expires
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function makeKey(Connection $connection, KeyState $state, string $fingerprint, bool $expires = true): ConnectionKey
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::CLIENT_ASSERTION,
            'state'         => $state,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'public_key'    => 'public-key-pem',
            'private_key'   => 'encrypted-private-key',
            'fingerprint'   => $fingerprint,
            'not_after'     => $expires ? new \DateTimeImmutable('2027-01-01T00:00:00Z') : null,
        ])->save();

        return $key;
    }

    /**
     * The reporter, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Administration\AdministrationEvents
     */
    private function events(): AdministrationEvents
    {
        return app(AdministrationEvents::class);
    }
}
