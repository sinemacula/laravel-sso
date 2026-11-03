<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SingleUseStore;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use Tests\Integration\Examples\ExampleTestCase;
use Tests\Integration\Examples\ScheduledPrune;

/**
 * The pruning example of `docs/guides/single-use-store.md` (SSO-11.5,
 * SSO-12.5), on the shared example harness: the schedule the guide's
 * `routes/console.php` holds runs `model:prune` hourly, naming the package's
 * single-use keys; run, it deletes the one key whose expiry has passed and
 * keeps the live one, which is still `seen`, while the expired one is recorded
 * again; run again, it deletes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SingleUseKey::class)]
#[CoversClass(DatabaseSingleUseStore::class)]
final class SingleUseStorePruneExampleTest extends ExampleTestCase
{
    /** @var string The application's namespace of invitations. */
    private const string INVITATIONS = 'app.invitations';

    /**
     * The scheduled `model:prune` deletes only the key whose expiry has passed.
     *
     * @return void
     */
    public function testTheScheduledPruneDeletesOnlyExpiredKeys(): void
    {
        $store = app(SingleUseStore::class);
        $now   = $this->clock->now();

        self::assertSame(SingleUseOutcome::RECORDED, $store->record(self::INVITATIONS, 'token-a', $now->addMinute()));
        self::assertSame(SingleUseOutcome::RECORDED, $store->record(self::INVITATIONS, 'token-b', $now->addHour()));

        $this->clock->advance(60);

        require __DIR__ . '/console.php';

        $scheduled = ScheduledPrune::scheduled();

        self::assertSame(['expression' => '0 * * * *', 'models' => [SingleUseKey::class]], $scheduled);
        self::assertSame([SingleUseKey::class => 1], ScheduledPrune::run($scheduled['models']));

        self::assertSame(SingleUseOutcome::SEEN, $store->record(self::INVITATIONS, 'token-b', $now->addHour()));
        self::assertSame(SingleUseOutcome::RECORDED, $store->record(self::INVITATIONS, 'token-a', $now->addHour()));
        self::assertSame([], ScheduledPrune::run($scheduled['models']));
    }
}
