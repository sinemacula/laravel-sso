<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\Events\ModelsPruned;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;

/**
 * Finds and runs the `model:prune` an application's schedule holds, for the
 * rate limit and single-use store examples.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScheduledPrune
{
    /** @var string The command the schedule runs. */
    private const string COMMAND = 'model:prune';

    /**
     * The one scheduled `model:prune`: its cron expression and the models its
     * `--model` option names, in order.
     *
     * @return array{expression: string, models: list<string>}
     */
    public static function scheduled(): array
    {
        $found = [];

        foreach (app(Schedule::class)->events() as $event) {

            $command = (string) $event->command;

            if (!str_contains($command, ' ' . self::COMMAND . ' ')) {
                continue;
            }

            preg_match_all('/--model=([\'"])(.*?)\1/', $command, $named);

            $found[] = ['expression' => $event->expression, 'models' => $named[2]];
        }

        Assert::assertCount(1, $found, 'The schedule holds one model:prune.');

        return $found[0];
    }

    /**
     * Run `model:prune` with the models, and answer how many rows of each it
     * deleted; a model that deleted none is not named.
     *
     * @param  list<string>  $models
     * @return array<string, int>
     */
    public static function run(array $models): array
    {
        /** @var \ArrayObject<string, int> $pruned */
        $pruned = new \ArrayObject;

        Event::listen(ModelsPruned::class, static function (ModelsPruned $event) use ($pruned): void {
            $pruned[$event->model] = ($pruned[$event->model] ?? 0) + $event->count;
        });

        Assert::assertSame(0, Artisan::call(self::COMMAND, ['--model' => $models]));

        return $pruned->getArrayCopy();
    }
}
