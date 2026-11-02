<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStatus;
use SineMacula\Laravel\Sso\Completion\Rules\LinkRules;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\LinkBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkingCheck;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Links\FixedLinker;

/**
 * Feature tests of the explicit link-storage capability (SSO-8.8,
 * `docs/design/linking.md`): whatever writes a link validates the configured
 * pairing and refuses before writing anything when the bound linker is not
 * backed by it, with a `LogicException` naming the problem; a boot check
 * reports it while linking by a verified domain is on; and a wrapper that
 * delegates to the store does everything the store does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkStorageBinding::class)]
#[CoversClass(LinkingCheck::class)]
#[CoversClass(LinkBranch::class)]
#[CoversClass(LinkRules::class)]
#[CoversClass(ProvisioningHelper::class)]
#[CoversClass(LinkingPolicyService::class)]
final class LinkStorageBindingTest extends LinkingTestCase
{
    /**
     * Bind an eligibility that lets every identity link, and a fresh caller.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
    }

    /**
     * The store and a wrapper are storage, and answered as bound; the default
     * and a linker that only resolves are none, and the problem names the
     * linker, the contract and the way out.
     *
     * @return void
     */
    public function testThePairingIsJudgedByTheBoundLinker(): void
    {
        $binding = app(LinkStorageBinding::class);
        $wrapper = new DelegatingLinkStorage(app(LinkStore::class));

        self::assertInstanceOf(LinkStore::class, $binding->find());
        self::assertInstanceOf(LinkStore::class, $binding->require('Anything'));

        $this->app?->instance(Linker::class, $wrapper);

        self::assertSame($wrapper, $binding->require('Anything'));

        $this->app?->instance(Linker::class, new NoLinks);

        self::assertNull($binding->find());

        try {
            $binding->require('Anything');
            self::fail('A linker with no storage was answered as storage.');
        } catch (\LogicException $exception) {
            self::assertSame(
                sprintf(
                    'Anything needs links its resolver reads, but the [%s] bound as [%s] does not implement [%s]: bind [%s], or a wrapper that delegates to it.',
                    NoLinks::class,
                    Linker::class,
                    LinkStorage::class,
                    LinkStore::class,
                ),
                $exception->getMessage(),
            );
        }
    }

    /**
     * While the feature is on the boot check reports a linker with no storage,
     * under the check's own subject; with storage, a wrapper or the feature off
     * there is nothing to report.
     *
     * @return void
     */
    public function testTheBootCheckReportsAPairingThatCannotLink(): void
    {
        $bound = app(ConfigurationChecker::class)->report();

        self::assertSame([], $bound['linking']);

        $this->app?->instance(Linker::class, new DelegatingLinkStorage(app(LinkStore::class)));

        $wrapped = app(ConfigurationChecker::class)->report();

        self::assertSame([], $wrapped['linking']);

        $this->app?->instance(Linker::class, new NoLinks);

        $found = app(ConfigurationChecker::class)->report();

        self::assertCount(1, (array) $found['linking']);
        self::assertStringStartsWith('The `domain_linking` feature needs links its resolver reads', $found['linking'][0] ?? '');

        config()->set('sso.features.domain_linking', false);

        $off = app(ConfigurationChecker::class)->report();

        self::assertSame([], $off['linking']);
    }

    /**
     * Turning linking on over a linker with no storage is refused, with nothing
     * written; turning it off needs no storage.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSettingsRefuseToTurnLinkingOnWithNoStorage(): void
    {
        $this->connection->forceFill(['linking_enabled' => false])->save();

        $version = $this->connection->refresh()->linking_version;

        $this->app?->instance(Linker::class, new NoLinks);

        try {
            app(LinkingPolicyService::class)->change('tenant-1', $this->connection->id, ['enabled' => true]);
            self::fail('Linking went on over a linker that would ignore its rows.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('Linking by a verified domain needs links its resolver reads', $exception->getMessage());
        }

        self::assertFalse($this->connection->refresh()->linking_enabled);
        self::assertSame($version, $this->connection->linking_version);

        $this->connection->forceFill(['linking_enabled' => true])->save();

        self::assertTrue(app(LinkingPolicyService::class)->change('tenant-1', $this->connection->id, ['enabled' => false])->isChanged());
    }

    /**
     * A `link` over a linker with no storage is refused at completion, with
     * nothing written and no code issued.
     *
     * @return void
     */
    public function testALinkCompletionRefusesWithNoStorage(): void
    {
        $this->start(Purpose::LINK, $this->person);

        $this->app?->instance(Linker::class, new FixedLinker(null));

        try {
            $this->complete();
            self::fail('A link went on over a linker that would ignore it.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('A [link] flow needs links its resolver reads', $exception->getMessage());
        }

        self::assertSame(0, Link::query()->count());
        self::assertSame(0, StoredCode::query()->count());
    }

    /**
     * A `link` redeemed over a linker with no storage is refused, with nothing
     * written and the code unconsumed; the same code goes through once it is
     * put right.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkRedemptionRefusesWithNoStorage(): void
    {
        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        $this->app?->instance(Linker::class, new FixedLinker(null));

        try {
            $this->connection->getConnection()->transaction(fn (): RedemptionResult => $this->admit($completion, $start, Purpose::LINK, $this->person));
            self::fail('A link was redeemed over a linker that would ignore it.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('A [link] redemption needs links its resolver reads', $exception->getMessage());
        }

        self::assertSame(0, Link::query()->count());
        self::assertNull(StoredCode::query()->sole()->redeemed_at);

        $this->app?->instance(Linker::class, app(LinkStore::class));

        self::assertTrue($this->admit($completion, $start, Purpose::LINK, $this->person)->isRedeemed());
    }

    /**
     * A `link` through a wrapper that delegates creates and resolves through
     * it.
     *
     * @return void
     */
    public function testALinkThroughAWrapperIsMade(): void
    {
        $wrapper = new DelegatingLinkStorage(app(LinkStore::class));

        $this->app?->instance(Linker::class, $wrapper);

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();
        $answer     = app(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            'web',
            $this->connection->id,
            (string) $completion->handoff?->code->reveal(),
            (string) $start->verifier?->reveal(),
            $this->person,
        );

        self::assertTrue($answer->isRedeemed());
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame(3, $wrapper->resolutions, 'At completion, in the judgement and in the admission.');
    }

    /**
     * The provisioning helper refuses over a linker with no storage before it
     * claims the grant or writes anything; the listener catches the exception,
     * so the completion goes on, finds the subject still unlinked and ends
     * `unlinked`, with nothing linked.
     *
     * @return void
     */
    public function testTheHelperRefusesWithNoStorageBeforeSpendingTheGrant(): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        $usable = null;

        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use (&$usable): void {

            $this->app?->instance(Linker::class, new FixedLinker(null));

            try {
                app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->person);
                self::fail('The helper wrote through a linker that would ignore it.');
            } catch (\LogicException $exception) {
                self::assertStringStartsWith('The provisioning helper needs links its resolver reads', $exception->getMessage());
            }

            $usable = $event->grant->isUsable();

            $this->app?->instance(Linker::class, app(LinkStore::class));
        });

        $this->start();

        $completion = $this->complete();

        self::assertTrue($usable);
        self::assertSame(0, Link::query()->count());
        self::assertSame([CompletionStatus::FAILED, FailureReason::UNLINKED], [$completion->status, $completion->reason]);
    }

    /**
     * The provisioning helper through a wrapper that delegates makes the link
     * the wrapper then resolves.
     *
     * @return void
     */
    public function testTheHelperThroughAWrapperLinks(): void
    {
        $this->matcher->match = LinkEmailMatch::none();

        $wrapper = new DelegatingLinkStorage(app(LinkStore::class));

        $this->app?->instance(Linker::class, $wrapper);

        $answer = null;

        Event::listen(ResultUnlinked::class, function (ResultUnlinked $event) use (&$answer): void {
            $answer = app(ProvisioningHelper::class)->link($event->grant, $event->result, $this->person);
        });

        $this->start();

        $completion = $this->complete();

        self::assertInstanceOf(ProvisioningResult::class, $answer);
        self::assertSame(ProvisioningStatus::CREATED, $answer->status);
        self::assertSame(LinkOrigin::PROVISIONING, Link::query()->sole()->provenance);
        self::assertTrue($completion->isCompleted());
        self::assertSame(2, $wrapper->resolutions, 'Before the boundary and in the final continuation.');
    }
}
