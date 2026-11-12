<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The `sso.pruning` settings, read on each call and failing closed when
 * malformed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PruneSettings
{
    /** @var int The retention when none is configured, in seconds (a day). */
    public const int DEFAULT_RETENTION_SECONDS = 86400;

    /** @var int The greatest retention that may be configured, in seconds (90 days). */
    public const int MAX_RETENTION_SECONDS = 7776000;

    /** @var int The batch when none is configured, in rows. */
    public const int DEFAULT_BATCH_SIZE = 1000;

    /** @var int The greatest batch, in rows; well inside every engine's bound parameter limit. */
    public const int MAX_BATCH_SIZE = 10000;

    /** @var int The work cap when none is configured, in rows of each kind. */
    public const int DEFAULT_MAX_ROWS_PER_KIND = 100000;

    /** @var int The greatest work cap that may be configured, in rows of each kind. */
    public const int MAX_MAX_ROWS_PER_KIND = 100000000;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private Repository $config,
    ) {}

    /**
     * How long past its expiry a request or a code is kept, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function retentionSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.pruning.retention_seconds', self::DEFAULT_RETENTION_SECONDS, 0, self::MAX_RETENTION_SECONDS);
    }

    /**
     * How many primary keys one statement names.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function batchSize(): int
    {
        return IntegerSetting::read($this->config, 'sso.pruning.batch_size', self::DEFAULT_BATCH_SIZE, 1, self::MAX_BATCH_SIZE);
    }

    /**
     * How many eligible rows one run looks at for each kind.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxRowsPerKind(): int
    {
        return IntegerSetting::read($this->config, 'sso.pruning.max_rows_per_kind', self::DEFAULT_MAX_ROWS_PER_KIND, 1, self::MAX_MAX_ROWS_PER_KIND);
    }
}
