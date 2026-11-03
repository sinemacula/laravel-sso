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
 * The example application's own single-use store (SSO-11.5), giving every
 * guarantee the contract asks for: one table of the application's, on the
 * package's storage connection so a record made in one of the package's
 * transactions is undone with it, shared by every server, read and written on
 * the write connection. Its primary key on the namespace and the key's digest
 * answers, so of two concurrent records of one key exactly one goes in. It
 * keeps a key until its expiry, to the microsecond in UTC, and only the key's
 * SHA-256 digest, never the key; a malformed record is refused with a message
 * that never holds the key, and any database error is thrown, never answered.
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

    /** @var string A namespace: 1 to 64 lower case letters, digits, `_`, `.`, `:` and `-`. */
    private const string NAMESPACE_PATTERN = '/^[a-z0-9_.:\-]{1,64}$/D';

    /** @var string The form an expiry is kept in, which sorts as the instants do. */
    private const string TIME_FORMAT = 'Y-m-d H:i:s.u';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock an expiry is judged against: the package's, so both agree on now. */
        private Clock $clock,
    ) {}

    /**
     * Record the key in the namespace until the expiry, unless it is held
     * there: a row whose expiry has passed holds nothing and goes first, then
     * one insert the primary key decides.
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
     * The keys table, on the storage connection, read from its write side.
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
