<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\ReinitiatingDriver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
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
 * The `saml2` driver (SSO-2.2, SSO-2.3, SSO-5.3, SSO-5.8, SSO-5.9, SSO-6): one
 * SAML 2.0 connection's flows, each through a collaborator of its own, with the
 * connection's settings read afresh into `Saml2Options` on every call.
 *
 * - `settings()` reads `Saml2Settings`.
 * - `isComplete()`: the settings are complete (`Saml2Settings::isComplete()`),
 *   the connection trusts at least one identity provider signing certificate,
 *   and it has a current service provider signing key when it signs its
 *   `AuthnRequest`s and a current encryption key when it requires encrypted
 *   assertions. Only a complete, enabled connection is used (SSO-2.1).
 * - `start()` (`AuthnRequests`), `complete()` (`ResponseValidator`) and
 *   `reinitiate()` (`UnsolicitedResponses`) are refused with
 *   `metadata_expired`, before their collaborator is asked, while what a
 *   metadata refresh applied to the connection has expired
 *   (`Metadata\MetadataExpiry`, SSO-2.8).
 * - `correlate()` (`ResponseCorrelator`) reads which request a response
 *   answers, validating nothing.
 * - `describe()` (`ServiceProviderMetadata`) is the service provider metadata.
 *
 * Every library call is made inside the SAML adapter's namespace (`Library`,
 * entered through `Library\SamlAdapter`); the driver and its collaborators read
 * only the package's own values. The protocol manager keeps one instance per
 * process (and per application under Octane), so it and its collaborators hold
 * no connection, flow or result state between calls (SSO-11.2), and never touch
 * the package's storage beyond the reads of the key ring and the metadata
 * expiry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Saml2Driver implements ProtocolDriver, ReinitiatingDriver
{
    /** @var string The name the driver is registered under, and a SAML connection's protocol. */
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
     * Validate the response against the consumed request, unless the
     * connection's metadata expired.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed): Completion
    {
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
     * Where re-initiation sends the browser for the connection, or `null` when
     * it does not allow IdP-initiated sign-in.
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
     * Whether the connection has a current key of the use, when it needs one.
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
