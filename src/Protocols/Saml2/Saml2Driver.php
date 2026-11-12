<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\ReinitiatingDriver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Reinitiation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;

/**
 * The `saml2` protocol driver. Settings are read afresh on every call; library
 * calls stay inside the `Library` namespace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Saml2Driver implements ProtocolDriver, ReinitiatingDriver
{
    /** @var string The driver's registered name and a SAML connection's protocol. */
    public const string NAME = 'saml2';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $metadata
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\AuthnRequests  $requests
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\ResponseCorrelator  $correlator
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\ResponseValidator  $validator
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\UnsolicitedResponses  $unsolicited
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\ServiceProviderMetadata  $description
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The connection's keys and trusted certificates. */
        private KeyRing $keys,

        /** Whether what a metadata refresh applied has expired. */
        private MetadataExpiry $metadata,

        /** Starts an SP-initiated sign-in. */
        private AuthnRequests $requests,

        /** Reads which request a response answers. */
        private ResponseCorrelator $correlator,

        /** Validates a solicited or unsuccessful response. */
        private ResponseValidator $validator,

        /** Validates an unsolicited response for re-initiation. */
        private UnsolicitedResponses $unsolicited,

        /** Describes the service provider side. */
        private ServiceProviderMetadata $description,
    ) {}

    /**
     * The SAML settings the values give.
     *
     * @param  array<array-key, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
     */
    #[\Override]
    public function settings(array $values): ProtocolSettings
    {
        return Saml2Settings::fromArray($values);
    }

    /**
     * Whether the connection's settings are complete, it trusts a signing
     * certificate, and it has each current key its settings need.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function isComplete(SsoConnection $connection): bool
    {
        if (!Saml2Settings::fromArray($connection->getSettings())->isComplete()) {
            return false;
        }

        $options = Saml2Options::of($connection);
        $id      = $connection->getConnectionId();

        return $this->keys->trustedCertificates($id) !== []
            && $this->hasKeyIfNeeded($id, $options->isOn(Saml2Setting::SIGN_AUTHN_REQUESTS), KeyUse::SP_SIGNING)
            && $this->hasKeyIfNeeded($id, $options->isOn(Saml2Setting::REQUIRE_ENCRYPTED_ASSERTIONS), KeyUse::SP_ENCRYPTION);
    }

    /**
     * Start an SP-initiated sign-in, unless the connection's metadata expired.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    #[\Override]
    public function start(SsoConnection $connection, StartRequest $request): Start
    {
        if ($this->metadata->isExpired($connection)) {
            return Start::refused(FailureReason::METADATA_EXPIRED);
        }

        return $this->requests->start($connection, Saml2Options::of($connection), $request);
    }

    /**
     * Read which request the response answers.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
    {
        return $this->correlator->correlate($connection, $request);
    }

    /**
     * Validate the response, unless the connection's metadata expired. SAML
     * reports nothing, so the client is unused.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed, ClientContext $client): Completion
    {
        unset($client);

        if ($this->metadata->isExpired($connection)) {
            return Completion::refused(FailureReason::METADATA_EXPIRED);
        }

        return $this->validator->complete($connection, Saml2Options::of($connection), $request, $consumed);
    }

    /**
     * Validate an unsolicited response for re-initiation, unless the
     * connection's metadata expired.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Reinitiation
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function reinitiate(SsoConnection $connection, CompletionRequest $request): Reinitiation
    {
        if ($this->metadata->isExpired($connection)) {
            return Reinitiation::refused(FailureReason::METADATA_EXPIRED);
        }

        return $this->unsolicited->reinitiate($connection, Saml2Options::of($connection), $request);
    }

    /**
     * Where re-initiation sends the browser, or `null` when it is off.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return ?string
     */
    #[\Override]
    public function startUrl(SsoConnection $connection): ?string
    {
        return $this->unsolicited->startUrl($connection, Saml2Options::of($connection));
    }

    /**
     * Describe the connection's service provider side.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function describe(SsoConnection $connection): ServiceProviderDescription
    {
        return $this->description->describe($connection, Saml2Options::of($connection));
    }

    /**
     * Whether the connection has a current key of the use, if it needs one.
     *
     * @param  string  $connectionId
     * @param  bool  $needed
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function hasKeyIfNeeded(string $connectionId, bool $needed, KeyUse $use): bool
    {
        return !$needed || $this->keys->current($connectionId, $use) !== null;
    }
}
