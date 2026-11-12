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
 * The example application's provisioning listener, naming each new person
 * `person-<n>` in memory.
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
