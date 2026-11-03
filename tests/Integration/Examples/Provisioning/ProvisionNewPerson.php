<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Provisioning;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;

/**
 * The provisioning listener of `docs/guides/provisioning.md` (SSO-8.6,
 * SSO-12.5): for a `sign_in` that resolved to nobody, a new user and their
 * membership of the result's tenant, linked to the result through the package's
 * helper with the grant the event carries, in one transaction on the package's
 * storage connection, committed when the link is made and rolled back on a
 * refusal or an exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvisionNewPerson
{
    // @snippet-start provisioning-listener
    /**
     * Take the helper that links the result to the new person.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper  $provisioning
     */
    public function __construct(

        /** Links the result to a new identity, once, with the event's grant. */
        private ProvisioningHelper $provisioning,
    ) {}

    /**
     * Create a new user and their membership, and link the result to them, in
     * one transaction on the package's storage connection.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return void
     *
     * @throws \Throwable
     */
    public function handle(ResultUnlinked $event): void
    {
        $storage = DB::connection(StorageConnection::name());

        $storage->beginTransaction();

        try {
            // Always a new user: never one found by an attribute
            $user = User::create(['name' => $event->result->attributes['display_name'] ?? 'New person']);

            $user->memberships()->create(['tenant_id' => $event->result->tenantId]);

            $identity = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

            $answer = $this->provisioning->link($event->grant, $event->result, $identity);
        } catch (\Throwable $exception) {
            $storage->rollBack();

            throw $exception;
        }

        if (!$answer->isCreated()) {

            // A refusal wrote nothing, so neither does the listener
            $storage->rollBack();

            return;
        }

        $storage->commit();
    }
    // @snippet-end provisioning-listener
}
