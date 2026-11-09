<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Standalone;

use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * An application's linker, as a standalone application writes one: a wrapper of
 * the package's link store that answers `Contracts\LinkStorage`, so a link the
 * package writes is one this linker resolves. It counts what it resolves and
 * records the origin of each link it is asked to create, and changes nothing
 * else about what the store does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationLinker implements LinkStorage
{
    /** @var int How many results it was asked to resolve. */
    public int $resolutions = 0;

    /** @var list<\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin> The origin of each link it was asked to create, in order. */
    public array $created = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkStorage  $store
     */
    public function __construct(

        /** The storage every method goes to. */
        private readonly LinkStorage $store,
    ) {}

    /**
     * What the store resolves the result to.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     */
    #[\Override]
    public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
    {
        $this->resolutions++;

        return $this->store->resolve($result, $client);
    }

    /**
     * What the store counts.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return int
     */
    #[\Override]
    public function holdings(string $connectionId, IdentityReference $identity): int
    {
        return $this->store->holdings($connectionId, $identity);
    }

    /**
     * Create through the store.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return \SineMacula\Laravel\Sso\Links\LinkCreation
     */
    #[\Override]
    public function create(
        SsoConnection $connection,
        LinkSubject $subject,
        IdentityReference $identity,
        LinkOrigin $origin,
        ClientContext $client,
        ?Caller $caller = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): LinkCreation {
        $this->created[] = $origin;

        return $this->store->create($connection, $subject, $identity, $origin, $client, $caller, $application, $purpose, $reference);
    }

    /**
     * Confirm through the store.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $locked
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     */
    #[\Override]
    public function confirm(SsoConnection $locked, string $linkId, ClientContext $client, ?string $application = null, ?RequestReference $reference = null): void
    {
        $this->store->confirm($locked, $linkId, $client, $application, $reference);
    }

    /**
     * Suspend through the store.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     */
    #[\Override]
    public function suspend(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId, string $protocol, ClientContext $client): void
    {
        $this->store->suspend($linkId, $identity, $connectionId, $tenantId, $protocol, $client);
    }

    /**
     * Revoke through the store.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @return void
     */
    #[\Override]
    public function revokeSessions(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId): void
    {
        $this->store->revokeSessions($linkId, $identity, $connectionId, $tenantId);
    }

    /**
     * The reservations of the store.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkReservations
     */
    #[\Override]
    public function reservations(): LinkReservations
    {
        return $this->store->reservations();
    }
}
