<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use SineMacula\Laravel\Sso\Enforcement\LockedEnforcement;
use SineMacula\Laravel\Sso\Linking\LinkingDiscovery;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * The rows a completion's transaction holds locked, in the package's order
 * (`flows.md`): the identity's guard when a reservation may be made, the
 * enforcing tenant's rule and connections when the default contract applies,
 * the relevant domain claim, the request. It lives only for the transaction it
 * was taken in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CompletionLock
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\LockedEnforcement  $enforcement
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  ?\SineMacula\Laravel\Sso\Linking\LinkingDiscovery  $discovery
     */
    public function __construct(

        /** The connection's row, or `null` when it is gone. */
        public ?Connection $connection,

        /** The request's row, or `null` when it is gone. */
        public ?AuthorizationRequest $request,

        /** The enforcement locked, when the default contract applies. */
        public ?LockedEnforcement $enforcement,

        /** The connection's claim of the linking email's domain, when there is one. */
        public ?Domain $domain,

        /** What plain reads found to lock before these were taken. */
        public ?LinkingDiscovery $discovery = null,
    ) {}
}
