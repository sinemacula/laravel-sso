<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A connection's metadata was fetched, validated whole and applied; it names
 * the settings that changed, never their values.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MetadataRefreshed implements SsoEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  list<string>  $changedSettings
     * @param  int  $metadataVersion
     * @param  bool  $trustChanged
     */
    public function __construct(

        /** Who asked for the refresh, if anyone, and for which connection. */
        public EventContext $context,

        /** The names of the settings the refresh changed, in order, each once. */
        public array $changedSettings,

        /** The connection's metadata version after the refresh. */
        public int $metadataVersion,

        /** Whether the refresh changed trust, voiding the flows in flight. */
        public bool $trustChanged,
    ) {}

    /**
     * Return who and what the refresh concerned.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
