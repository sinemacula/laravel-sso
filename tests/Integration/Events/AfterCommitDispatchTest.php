<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests of the after-commit dispatch with the storage connection
 * moved to a second connection, beside the suite's own database: an event
 * reporting a write made there is delivered when that write commits and dropped
 * when it rolls back, whatever the suite's database does, and a queued listener
 * receives the failure event with its context intact.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommitDispatcher::class)]
#[CoversClass(EventContexts::class)]
#[CoversClass(FlowFailed::class)]
final class AfterCommitDispatchTest extends TestCase
{
    /** @var string The connection the package's tables are moved to. */
    private const string STORE = 'sso_events_store';

    /** @var string The table the tests write to on the storage connection. */
    private const string TABLE = 'sso_event_writes';

    /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Contracts\SsoEvent> The package events delivered synchronously, in order. */
    private \ArrayObject $delivered;

    /**
     * Bind the fixed clock, create the table on the storage connection, and
     * record every package event delivered.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-10-31T12:00:00.654321Z'));

        Schema::connection(self::STORE)->create(self::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->string('reference');
        });

        $delivered = new \ArrayObject;

        Event::listen(SsoEvent::class, static function (SsoEvent $event) use ($delivered): void {
            $delivered->append($event);
        });

        $this->delivered = $delivered;
    }

    /**
     * Drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(self::STORE)->dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * An event dispatched in a transaction on the storage connection is
     * delivered once that transaction commits its write, and not before, even
     * though a transaction on the suite's database rolls back meanwhile.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventIsDeliveredWhenItsWriteCommits(): void
    {
        $event = $this->failure();
        $store = DB::connection(self::STORE);

        $store->beginTransaction();
        $store->table(self::TABLE)->insert(['reference' => 'ref_1']);

        DB::beginTransaction();

        $this->dispatcher()->dispatch($event);

        DB::rollBack();

        self::assertCount(0, $this->delivered);

        $store->commit();

        self::assertSame(1, $store->table(self::TABLE)->count());
        self::assertSame([$event], $this->delivered->getArrayCopy());
    }

    /**
     * An event dispatched in a transaction on the storage connection that rolls
     * back is never delivered, and its write is gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventIsDroppedWhenItsWriteRollsBack(): void
    {
        $store = DB::connection(self::STORE);

        $store->beginTransaction();
        $store->table(self::TABLE)->insert(['reference' => 'ref_1']);

        $this->dispatcher()->dispatch($this->failure());

        $store->rollBack();

        self::assertSame(0, $store->table(self::TABLE)->count());
        self::assertCount(0, $this->delivered);
    }

    /**
     * A queued listener, on the `sync` queue, which serialises the event as any
     * queue does, receives the failure event after its write commits, with its
     * flow, its reason and its context intact.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueuedListenerReceivesTheFailureIntact(): void
    {
        config()->set('queue.default', 'sync');

        $listener = new class implements ShouldQueue {
            /** @var list<\SineMacula\Laravel\Sso\Events\FlowFailed> The events received, in order. */
            private static array $received = [];

            /**
             * Forget the events received.
             *
             * @return void
             */
            public static function forget(): void
            {
                self::$received = [];
            }

            /**
             * The events received, in order.
             *
             * @return list<\SineMacula\Laravel\Sso\Events\FlowFailed>
             */
            public static function received(): array
            {
                return self::$received;
            }

            /**
             * Record the event as the queue hands it back.
             *
             * @param  \SineMacula\Laravel\Sso\Events\FlowFailed  $event
             * @return void
             */
            public function handle(FlowFailed $event): void
            {
                self::$received[] = $event;
            }
        };

        $listener::forget();

        Event::listen(FlowFailed::class, [$listener::class, 'handle']);

        $this->app?->instance('request', Request::create('/', 'POST', [], [], [], [
            'REMOTE_ADDR'     => '203.0.113.7',
            'HTTP_USER_AGENT' => 'Example/1.0',
        ]));

        $event = $this->failure();

        DB::connection(self::STORE)->transaction(function () use ($event, $listener): void {
            DB::connection(self::STORE)->table(self::TABLE)->insert(['reference' => 'ref_1']);

            $this->dispatcher()->dispatch($event);

            self::assertSame([], $listener::received());
        });

        self::assertCount(1, $listener::received());

        $received = $listener::received()[0];

        self::assertNotSame($event, $received);
        self::assertSame(Flow::ASSERTION, $received->flow);
        self::assertSame(FailureReason::SIGNATURE_INVALID, $received->reason);
        self::assertSame($event->context()->toArray(), $received->context()->toArray());
        self::assertSame([
            'occurred_at'                 => '2026-10-31T12:00:00.654321Z',
            'ip'                          => '203.0.113.7',
            'user_agent'                  => 'Example/1.0',
            'connection_id'               => 'conn_1',
            'tenant_id'                   => 'tenant_1',
            'protocol'                    => 'saml2',
            'application'                 => 'web',
            'purpose'                     => 'sign_in',
            'request_reference'           => 'ref_1',
            'identity_morph_class'        => null,
            'identity_id'                 => null,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'active_tenant_id'            => null,
            'session_id'                  => null,
            'method'                      => null,
        ], $received->context()->toArray());
    }

    /**
     * Add the second connection, and move the storage connection to it.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::STORE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('sso.storage.connection', self::STORE);
    }

    /**
     * Resolve the dispatcher from the container, as the package does.
     *
     * @return \SineMacula\Laravel\Sso\Events\AfterCommitDispatcher
     */
    private function dispatcher(): AfterCommitDispatcher
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(AfterCommitDispatcher::class);
    }

    /**
     * A refused assertion, its context built by the package's projection.
     *
     * @return \SineMacula\Laravel\Sso\Events\FlowFailed
     */
    private function failure(): FlowFailed
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $context = $app->make(EventContexts::class)->make(
            connectionId: 'conn_1',
            tenantId: 'tenant_1',
            protocol: 'saml2',
            application: 'web',
            purpose: 'sign_in',
            requestReference: 'ref_1',
        );

        return new FlowFailed($context, Flow::ASSERTION, FailureReason::SIGNATURE_INVALID);
    }
}
