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
 * The pruning example of `docs/guides/single-use-store.md`.
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
