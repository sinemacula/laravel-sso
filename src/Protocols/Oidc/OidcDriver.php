<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;

/**
 * The `oidc` driver (SSO-2.2, SSO-2.4, SSO-5.4, SSO-5.9, SSO-7): one OpenID
 * Connect connection's flows, each through a collaborator of its own, with the
 * connection's settings read afresh into `OidcOptions` on every call.
 *
 * - `settings()` reads `OidcSettings`.
 * - `isComplete()`: the settings are complete (`OidcSettings::isComplete()`),
 *   and the connection holds its client authentication's credential: a client
 *   secret for `client_secret_basic` and `client_secret_post`, a current
 *   `client_assertion` key that fits the connection's pinned algorithm for
 *   `private_key_jwt`. Only a complete, enabled connection is used (SSO-2.1).
 * - `start()` (`AuthorizationRequests`) and `complete()` (`CallbackCompletion`)
 *   are refused with `metadata_expired`, before their collaborator is asked,
 *   while what was fetched for the connection has expired (its discovery
 *   document or its JWKS, `Metadata\MetadataExpiry`, SSO-2.8).
 * - `correlate()` (`CallbackCorrelator`) reads which request a callback answers
 *   by its `state`, validating nothing.
 * - `describe()` (`RelyingPartyDescription`) is what an administrator registers
 *   at the provider, naming the public JWKS URL for `private_key_jwt`;
 *   `describeWithInlineKeys()` is the same document with the keys in it
 *   instead, for a provider that requires uploaded keys; and `publicKeys()` is
 *   the body of the public JWKS URL, which the application serves.
 *
 * Every JOSE library call is made inside the adapter's namespace
 * (`Protocols\Oidc\Jose`); the driver and its collaborators read only the
 * package's own values. The protocol manager keeps one instance per process
 * (and per application under Octane), so it and its collaborators hold no
 * connection, flow or result state between calls (SSO-11.2), and never touch
 * the package's storage beyond the reads of the key ring, the secrets, the
 * stored JWKS and the metadata expiry, and the JWKS refetch's own writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OidcDriver implements ProtocolDriver
{
    /** @var string The name the driver is registered under, and an OIDC connection's protocol. */
    public const string NAME = 'oidc';

    /** @var string The client authentication that signs a client assertion with the connection's own key. */
    private const string PRIVATE_KEY_JWT = 'private_key_jwt';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSecrets  $secrets
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $metadata
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationRequests  $requests
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCorrelator  $correlator
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCompletion  $callbacks
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\RelyingPartyDescription  $description
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The connection's own keys. */
        private KeyRing $keys,

        /** Whether the connection's client secret is set. */
        private ConnectionSecrets $secrets,

        /** Whether what was fetched has expired. */
        private MetadataExpiry $metadata,

        /** Starts an authorisation code flow. */
        private AuthorizationRequests $requests,

        /** Reads which request a callback answers. */
        private CallbackCorrelator $correlator,

        /** Completes a callback: the token request, the ID token and the claims. */
        private CallbackCompletion $callbacks,

        /** Describes the relying party side. */
        private RelyingPartyDescription $description,
    ) {}

    /**
     * The OIDC settings the values give.
     *
     * @param  array<array-key, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
     */
    #[\Override]
    public function settings(array $values): ProtocolSettings
    {
        return OidcSettings::fromArray($values);
    }

    /**
     * Whether the connection's settings are complete and it holds its client
     * authentication's credential.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function isComplete(SsoConnection $connection): bool
    {
        if (!OidcSettings::fromArray($connection->getSettings())->isComplete()) {
            return false;
        }

        if (OidcOptions::of($connection)->clientAuthentication() === self::PRIVATE_KEY_JWT) {
            return $this->holdsAssertionKey($connection);
        }

        return $this->secrets->isSet($connection, OidcSetting::CLIENT_SECRET->value);
    }

    /**
     * Start an authorisation code flow, unless what was fetched has expired.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function start(SsoConnection $connection, StartRequest $request): Start
    {
        if ($this->metadata->isExpired($connection)) {
            return Start::refused(FailureReason::METADATA_EXPIRED);
        }

        return $this->requests->start($connection, OidcOptions::of($connection), $request);
    }

    /**
     * Read which request the callback answers.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     */
    #[\Override]
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
    {
        return $this->correlator->correlate($connection, $request);
    }

    /**
     * Complete the callback against the consumed request, unless what was
     * fetched has expired.
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

        return $this->callbacks->complete($connection, OidcOptions::of($connection), $request, $consumed);
    }

    /**
     * Describe the connection's relying party side.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    #[\Override]
    public function describe(SsoConnection $connection): ServiceProviderDescription
    {
        return $this->description->describe($connection, OidcOptions::of($connection));
    }

    /**
     * Describe the connection's relying party side with its public keys in the
     * document, for a provider that requires uploaded keys.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    public function describeWithInlineKeys(SsoConnection $connection): ServiceProviderDescription
    {
        return $this->description->describeWithInlineKeys($connection, OidcOptions::of($connection));
    }

    /**
     * The body of the connection's public JWKS URL: its current and next public
     * keys.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    public function publicKeys(SsoConnection $connection): ServiceProviderDescription
    {
        return $this->description->publicKeys($connection, OidcOptions::of($connection));
    }

    /**
     * Whether the connection holds a current client assertion key that fits its
     * pinned algorithm.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function holdsAssertionKey(SsoConnection $connection): bool
    {
        $key = $this->keys->current($connection->getConnectionId(), KeyUse::CLIENT_ASSERTION);

        return $key !== null && ClientAssertionAlgorithm::fits(OidcOptions::of($connection)->clientAssertionAlgorithm(), $key->type);
    }
}
