<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * `[storage]`: where the package's tables live and what they are called, while
 * the package is in use (SSO-11.10). The storage connection and the counters'
 * connection must each be a connection name `database.connections` configures,
 * or none; every table's name must be a table name; and no two tables on one
 * connection may share a name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class StorageCheck implements ConfigurationCheck
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration checked. */
        private Repository $config,
    ) {}

    /**
     * Storage is checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * The two connections, each table's name, then that the names are distinct.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [
            fn (): ?string => $this->configured('storage.connection', StorageConnection::name()),
            fn (): ?string => $this->countersConnection(),
        ];

        foreach (array_keys(StorageConnection::TABLES) as $key) {
            $checks[] = static fn (): string => StorageConnection::table($key);
        }

        $checks[] = static function (): void {
            self::distinct();
        };

        return $checks;
    }

    /**
     * The counters' connection, once it is known to be well formed and, when
     * `sso.rate_limits.connection` names its own, configured. When it names
     * none the counters live on the storage connection, which the check before
     * has already reported, so a missing one is reported once.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function countersConnection(): ?string
    {
        $connection = StorageConnection::forRateLimits();
        $own        = $this->config->get('sso.rate_limits.connection');

        return $own === null || $own === '' ? $connection : $this->configured('rate_limits.connection', $connection);
    }

    /**
     * The connection the setting names, once it is known to be configured in
     * `database.connections`; `null`, the default connection, always is.
     *
     * @param  string  $key
     * @param  ?string  $connection
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function configured(string $key, ?string $connection): ?string
    {
        if ($connection !== null && !is_array($this->config->get("database.connections.{$connection}"))) {
            throw new \InvalidArgumentException(sprintf('`sso.%s` names the connection [%s], which is not configured in `database.connections`.', $key, $connection));
        }

        return $connection;
    }

    /**
     * Refuse two tables of one connection with the same name. Settings the
     * other checks refuse are left to them.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function distinct(): void
    {
        $seen = [];

        foreach (array_keys(StorageConnection::TABLES) as $key) {

            try {
                $where = (StorageConnection::connectionFor($key) ?? '') . "\0" . strtolower(StorageConnection::table($key));
            } catch (\InvalidArgumentException) {
                continue;
            }

            if (isset($seen[$where])) {
                throw new \InvalidArgumentException(sprintf('`sso.%s` and `sso.%s` name the same table on the same connection.', $seen[$where], $key));
            }

            $seen[$where] = $key;
        }
    }
}
