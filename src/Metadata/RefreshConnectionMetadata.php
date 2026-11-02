<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;

/**
 * The queued refresh of one SAML connection's metadata (SSO-2.8, SSO-11.12),
 * which `sso:metadata:refresh` sends for each connection due, so fetching and
 * checking a large federation aggregate runs on a queue whose workers have the
 * memory and the time for it rather than in the scheduler.
 *
 * It carries the connection's id alone, never a URL, certificate or any value
 * of the metadata, and is sent on `sso.metadata.queue.connection` and
 * `sso.metadata.queue.name`, allowed `sso.metadata.queue.timeout_seconds`
 * (failing on a timeout rather than being retried past its claim) and
 * `sso.metadata.queue.tries` attempts. It hands the id to
 * `MetadataRefresher::refreshQueued()`, which reads the connection again and
 * refreshes it only while it is still due, so a job that waited in the queue
 * while another server refreshed the connection does nothing; the claim keeps
 * two jobs for one connection from both fetching. How the refresh ended is
 * reported by its events and logs.
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

    /** @var bool Whether a timeout fails the job rather than releasing it for another attempt. */
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

        // Not promoted: read once here for the queue options, never kept, since
        // only the id is serialised
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
        $refresher->refreshQueued($this->connectionId);
    }
}
