<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AuthnRequestWriter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Starts an SP-initiated SAML sign-in: writes the connection's `AuthnRequest`
 * and the navigation that sends it to the identity provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthnRequests
{
    /** @var int The most bytes a `RelayState` may have (SAML 2.0 Bindings 3.4.3 and 3.5.3). */
    public const int MAX_RELAY_STATE_BYTES = 80;

    /** @var int Random bytes in a request `ID`. */
    private const int ID_BYTES = 32;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Contracts\EndpointResolver  $endpoints
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\AuthnRequestWriter  $writer
     */
    public function __construct(

        /** The connection's service provider signing key. */
        private KeyRing $keys,

        /** The connection's entity id and assertion consumer service. */
        private EndpointResolver $endpoints,

        /** The clock the request is issued by. */
        private Clock $clock,

        /** Writes the request through the SAML adapter. */
        private AuthnRequestWriter $writer,
    ) {}

    /**
     * Start the request; refused when the connection lacks a single sign-on URL
     * or a signing key it needs.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function start(SsoConnection $connection, Saml2Options $options, StartRequest $request): Start
    {
        self::assertRelayState($request->state);

        $ssoUrl  = $options->ssoUrl;
        $signing = $options->isOn(Saml2Setting::SIGN_AUTHN_REQUESTS);
        $key     = $signing ? $this->signingKey($connection->getConnectionId()) : null;
        $keyless = $signing && $key === null;

        if ($ssoUrl === null || $keyless) {
            return Start::refused(FailureReason::CONNECTION_UNAVAILABLE);
        }

        $outgoing = $this->writer->write(
            self::requestId(),
            $this->clock->now(),
            $this->endpoints->endpoints($connection),
            $options,
            self::forcesAuthn($options, $request),
            $request->state,
            $key,
        );

        return Start::navigate(self::navigation($ssoUrl, $outgoing), $outgoing->id);
    }

    /**
     * The private half of the current SP signing key, if there is one.
     *
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     */
    private function signingKey(string $connectionId): ?Secret
    {
        $current = $this->keys->current($connectionId, KeyUse::SP_SIGNING);

        return $current === null ? null : $this->keys->privateKey($connectionId, $current->id);
    }

    /**
     * Refuse an over-long `RelayState`, revealing none of it.
     *
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $state
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertRelayState(#[\SensitiveParameter] Secret $state): void
    {
        if (strlen($state->reveal()) > self::MAX_RELAY_STATE_BYTES) {
            throw new \LogicException(sprintf('A SAML RelayState is at most %d bytes.', self::MAX_RELAY_STATE_BYTES));
        }
    }

    /**
     * A fresh request `ID`: `_` and 32 random bytes as lower-case hex.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private static function requestId(): string
    {
        return '_' . bin2hex(random_bytes(self::ID_BYTES));
    }

    /**
     * Whether the request forces fresh authentication.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return bool
     */
    private static function forcesAuthn(Saml2Options $options, StartRequest $request): bool
    {
        return $options->isOn(Saml2Setting::FORCE_AUTHN) || $request->purpose === Purpose::REAUTHENTICATE;
    }

    /**
     * A redirect or form post to the single sign-on URL.
     *
     * @param  string  $ssoUrl
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest  $outgoing
     * @return \SineMacula\Laravel\Sso\Protocols\Navigation
     *
     * @throws \InvalidArgumentException
     */
    private static function navigation(string $ssoUrl, OutgoingRequest $outgoing): Navigation
    {
        return $outgoing->isRedirect()
            ? Navigation::redirect(self::withQuery($ssoUrl, $outgoing->query()))
            : Navigation::post($ssoUrl, $outgoing->fields());
    }

    /**
     * The URL with the query appended.
     *
     * @param  string  $url
     * @param  string  $query
     * @return string
     */
    private static function withQuery(string $url, #[\SensitiveParameter] string $query): string
    {
        $separator = match (true) {
            !str_contains($url, '?')                           => '?',
            str_ends_with($url, '?'), str_ends_with($url, '&') => '',
            default                                            => '&',
        };

        return $url . $separator . $query;
    }
}
