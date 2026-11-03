<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Standalone;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * An application's single-use store, kept on a database connection of its own:
 * atomic under its primary key, keeping only a digest of each key, and read and
 * written on the write connection. It is the store the contract allows and the
 * documentation warns about: what it records is on no transaction of the
 * package's, so a record made inside one is kept when that transaction rolls
 * back (`docs/guides/single-use-store.md`).
 *
 * Its connection is the default connection's configuration under another name:
 * another database in memory on SQLite, and the same database through another
 * session on a server, so it runs on every engine the suite does. It keeps each
 * expiry as a sortable string, so it reads back the same on all of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationSingleUseStore implements SingleUseStore
{
    /** @var string The connection the store keeps its keys on. */
    public const string CONNECTION = 'standalone_single_use';

    /** @var string The table the store keeps its keys in. */
    public const string TABLE = 'standalone_single_use_keys';

    /** @var string The form an expiry is kept in. */
    private const string TIME_FORMAT = 'Y-m-d H:i:s.u';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock an expiry is judged against. */
        private Clock $clock,
    ) {}

    /**
     * Configure the store's connection and create its table there.
     *
     * @return void
     */
    public static function create(): void
    {
        Config::set('database.connections.' . self::CONNECTION, Config::array('database.connections.' . Config::string('database.default')));

        Schema::connection(self::CONNECTION)->create(self::TABLE, static function (Blueprint $table): void {
            $table->string('namespace', 64);
            $table->char('key_digest', 64);
            $table->string('held_until', 32);
            $table->primary(['namespace', 'key_digest']);
        });
    }

    /**
     * Drop the store's table.
     *
     * @return void
     */
    public static function drop(): void
    {
        Schema::connection(self::CONNECTION)->dropIfExists(self::TABLE);
    }

    /**
     * The namespace of each key held, in order.
     *
     * @return list<string>
     */
    public static function namespaces(): array
    {
        /** @var list<string> */
        return self::keys()->orderBy('namespace')->pluck('namespace')->all();
    }

    /**
     * Record the key in the namespace until the expiry, unless it is held
     * there, by one insert the primary key decides; a row whose expiry has
     * passed holds nothing and goes first.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function record(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until): SingleUseOutcome
    {
        $now = $this->clock->now();

        if ($key === '' || $until <= $now) {
            throw new \InvalidArgumentException('A key is recorded when it is not empty, until an expiry yet to come.');
        }

        $digest = hash('sha256', $key);

        self::keys()->where('namespace', $namespace)->where('key_digest', $digest)->where('held_until', '<=', self::stamp($now))->delete();

        $inserted = self::keys()->insertOrIgnore(['namespace' => $namespace, 'key_digest' => $digest, 'held_until' => self::stamp($until)]);

        return $inserted === 1 ? SingleUseOutcome::RECORDED : SingleUseOutcome::SEEN;
    }

    /**
     * The keys table, on the store's connection, read from its write side.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function keys(): Builder
    {
        return DB::connection(self::CONNECTION)->table(self::TABLE)->useWritePdo();
    }

    /**
     * The instant, as it is kept.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return string
     */
    private static function stamp(CarbonImmutable $instant): string
    {
        return $instant->utc()->format(self::TIME_FORMAT);
    }
}
