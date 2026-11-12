<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use SineMacula\Laravel\Sso\Http\ClientContext;

/**
 * The queued refresh of one connection's metadata, carrying its id alone, so a
 * large aggregate is fetched by a worker sized for it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RefreshConnectionMetadata implements ShouldQueue
{
    use Queueable;

    /** @var int The seconds the job may run before the worker stops it. */
    public readonly int $timeout;

    /** @var int How many times the job may be attempted. */
    public readonly int $tries;

    /** @var bool Whether a timeout fails the job rather than releasing it past its claim. */
    public readonly bool $failOnTimeout;

    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The connection whose metadata is refreshed. */
        public readonly string $connectionId,

        // Not promoted: read for the queue options; only the id is serialised
        MetadataSettings $settings,
    ) {
        $this->timeout       = $settings->timeoutSeconds();
        $this->tries         = $settings->tries();
        $this->failOnTimeout = true;

        $this->onConnection($settings->queueConnection());
        $this->onQueue($settings->queueName());
    }

    /**
     * Refresh the connection, if it is still due.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataRefresher  $refresher
     * @return void
     *
     * @throws \Throwable
     */
    public function handle(MetadataRefresher $refresher): void
    {
        $refresher->refreshQueued($this->connectionId, new ClientContext(null, null));
    }
}
