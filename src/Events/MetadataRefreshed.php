<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;

/**
 * A connection's metadata was refreshed (SSO-2.8, SSO-10.3): fetched from the
 * URL the administrator saved, validated whole, and applied. It names the
 * settings the refresh changed (`sso_url`, `sso_binding`,
 * `idp_signing_certificates`, say), never their values, and none when the
 * metadata was unchanged; the connection's metadata version after the refresh;
 * and whether the refresh changed its trust (removed or replaced a trusted
 * certificate, or moved the single sign-on endpoint), which voids every flow in
 * flight through it (SSO-2.10). Adding a signing certificate alone does not.
 *
 * Dispatched after the transaction that applied the refresh commits, and never
 * when it rolls back (SSO-10.5). Its context names the connection, its tenant
 * and protocol, and the acting identity when an administrator asked for the
 * refresh; a scheduled one has none (SSO-10.4). It reports only, and holds no
 * certificate, URL or other value of the metadata; it crosses a queue as it is.
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

        /** Who asked for the refresh, if anyone, and which connection it refreshed. */
        public EventContext $context,

        /** The names of the settings the refresh changed, in order, each once; none when nothing changed. */
        public array $changedSettings,

        /** The connection's metadata version after the refresh. */
        public int $metadataVersion,

        /** Whether the refresh removed or replaced a trusted certificate or moved the single sign-on endpoint, voiding the flows in flight. */
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
