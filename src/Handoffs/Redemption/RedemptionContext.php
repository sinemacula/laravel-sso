<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * What a purpose's branch of a redemption judges; valid only in the transaction
 * its locks were taken in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RedemptionContext
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @param  \SineMacula\Laravel\Sso\Handoffs\RecheckLock  $lock
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $linkProvenance
     */
    public function __construct(

        /** The verified result the code carried. */
        public VerifiedResult $result,

        /** What the code was bound to at completion. */
        public HandoffBinding $binding,

        /** The locks held. */
        public RecheckLock $lock,

        /** The connection, as locked. */
        public Connection $connection,

        /** The client the redemption is made for, which its events carry. */
        public ClientContext $client,

        /** The caller the application has authenticated, for a `link`. */
        public ?Caller $caller = null,

        /** The provenance of the link the judgement found, for an admission. */
        public ?LinkOrigin $linkProvenance = null,
    ) {}
}
