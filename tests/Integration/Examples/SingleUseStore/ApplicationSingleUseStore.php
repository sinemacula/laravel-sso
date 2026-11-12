<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SingleUseStore;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * A single-use store on the package's storage connection, so a record rolls
 * back with the package's transaction; the primary key decides concurrent
 * records, and only the key's SHA-256 digest is kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApplicationSingleUseStore implements SingleUseStore
{
    /** @var string The application's table the keys are held in. */
    public const string TABLE = 'single_use_keys';

    /** @var string 1 to 64 lower-case letters, digits, `_`, `.`, `:` and `-`. */
    private const string NAMESPACE_PATTERN = '/^[a-z0-9_.:\-]{1,64}$/D';

    /** @var string The expiry format, which sorts as the instants do. */
    private const string TIME_FORMAT = 'Y-m-d H:i:s.u';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The package's clock, so both agree on now. */
        private Clock $clock,
    ) {}

    /**
     * Record the key until the expiry: an expired row is deleted first, then
     * the primary key decides the insert.
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
        $now       = $this->clock->now();
        $malformed = preg_match(self::NAMESPACE_PATTERN, $namespace) !== 1 || $key === '';

        if ($malformed || $until <= $now) {
            throw new \InvalidArgumentException('A key is recorded when its namespace is well formed, it is not empty and its expiry is yet to come.');
        }

        $digest = hash('sha256', $key);

        self::keys()->where('namespace', $namespace)->where('key_digest', $digest)->where('expires_at', '<=', self::stamp($now))->delete();

        $inserted = self::keys()->insertOrIgnore(['namespace' => $namespace, 'key_digest' => $digest, 'expires_at' => self::stamp($until)]);

        return $inserted === 1 ? SingleUseOutcome::RECORDED : SingleUseOutcome::SEEN;
    }

    /**
     * The keys table, read from the storage connection's write side.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function keys(): Builder
    {
        return DB::connection(StorageConnection::name())->table(self::TABLE)->useWritePdo();
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
