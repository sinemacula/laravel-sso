<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Application;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper;
use Tests\Integration\Examples\Clients;

/**
 * The example application's provisioning listener (SSO-8.6): a new identity for
 * a `sign_in` that resolved to nobody, linked through the package's helper with
 * the grant the event carries, in one transaction on the package's storage
 * connection, rolled back when the helper refuses.
 *
 * It names each new person `person-<n>` and keeps them in memory, which is all
 * a test needs. An application's own listener creates the user and their
 * membership in the same transaction, never resolving an existing person from
 * the email or another attribute, as `docs/guides/provisioning.md` shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ProvisionNewPeople
{
    /** @var list<\SineMacula\Laravel\Sso\Identities\IdentityReference> Every person provisioned, in order. */
    private array $provisioned = [];

    /**
     * Provision a new person for the unlinked result.
     *
     * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
     * @return void
     *
     * @throws \Throwable
     */
    public function handle(ResultUnlinked $event): void
    {
        $person   = new IdentityReference('App\Models\User', 'person-' . (count($this->provisioned) + 1));
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            $answer = app(ProvisioningHelper::class)->link($event->grant, $event->result, $person, Clients::browser());
        } catch (\Throwable $exception) {
            $database->rollBack();

            throw $exception;
        }

        if (!$answer->isCreated()) {

            $database->rollBack();

            return;
        }

        $database->commit();

        $this->provisioned[] = $person;
    }

    /**
     * Every person provisioned, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Identities\IdentityReference>
     */
    public function provisioned(): array
    {
        return $this->provisioned;
    }
}
