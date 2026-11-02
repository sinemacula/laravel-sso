<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkingDiscovery;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\ReservedCandidate;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * What a completion has established so far (SSO-5.6), handed from each stage to
 * the next in `Enums\CompletionStep`'s order: the connection the response
 * arrived for and what arrived; the connection, read from the write connection;
 * the correlation the driver read; the authorisation request, consumed, with
 * what the driver is given of it and the registered application; the
 * enforcement policy as the locks the completion holds show it; the claims the
 * driver verified, what records them against replay, and the result built from
 * them; the identity the result's link resolved to; the enforcement version
 * checked; the latest end of the application's session the provider's deadline
 * sets; the handoff issued; the receipt of a key rotation the response's own
 * validation made; how the result's link resolved; the candidate a reservation
 * holds, which is never the resolved identity; the domain claim locked for
 * linking; the linking policy version the response was validated under; when
 * the verified response stops being valid, which no continuation extends; and
 * what plain reads found to lock before its locked transaction.
 *
 * An unsolicited SAML response handed to re-initiation (SSO-5.8) only ever
 * holds the connection, its correlation and, under the connection's lock, its
 * replay record: no request, application, claims, result or identity, so
 * nothing of it carries into the flow the application starts next.
 *
 * Each `with…()` answers a new state with one part added and the rest kept;
 * nothing is ever removed. It lives only for the completion it describes: it
 * holds the response, the consumed request and the issued code, so a dump shows
 * only ids and what is set, and it refuses to be serialised or unserialised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CompletionState
{
    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest  $authorizationRequest
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $enforcementPolicy
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @param  ?string  $enforcementVersion
     * @param  ?\Carbon\CarbonImmutable  $sessionNotAfter
     * @param  ?\SineMacula\Laravel\Sso\Handoffs\IssuedHandoff  $handoff
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ReplayRecord  $replay
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $transitionReceipt
     * @param  ?\SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @param  ?\SineMacula\Laravel\Sso\Links\ReservedCandidate  $reservedCandidate
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $linkingDomain
     * @param  ?int  $linkingVersion
     * @param  ?\Carbon\CarbonImmutable  $verifiedUntil
     * @param  ?\SineMacula\Laravel\Sso\Linking\LinkingDiscovery  $linkingDiscovery
     *
     * @SuppressWarnings("php:S107")
     */
    private function __construct(

        /** The id of the connection whose endpoint the response arrived at, as the application's route gave it. */
        public string $connectionId,

        /** What arrived at the endpoint. */
        public CompletionRequest $request,

        /** The connection, read from the write connection. */
        public ?Connection $connection = null,

        /** Which request the driver read the response as answering. */
        public ?Correlation $correlation = null,

        /** The authorisation request, consumed. */
        public ?AuthorizationRequest $authorizationRequest = null,

        /** What the driver is given of the consumed request. */
        public ?ConsumedRequest $consumed = null,

        /** The registered application the request is for. */
        public ?Application $application = null,

        /** The enforcement policy judged from the rows the completion holds locked, when the default contract locked them. */
        public ?EnforcementPolicy $enforcementPolicy = null,

        /** What the driver verified. */
        public ?VerifiedClaims $claims = null,

        /** The verified result built from the claims. */
        public ?VerifiedResult $result = null,

        /** The identity the result's link resolved to, if any. */
        public ?IdentityReference $linkedIdentity = null,

        /** The enforcement version the completion checked. */
        public ?string $enforcementVersion = null,

        /** The latest end of the application's session the provider's deadline sets. */
        public ?CarbonImmutable $sessionNotAfter = null,

        /** The handoff issued. */
        public ?IssuedHandoff $handoff = null,

        /** What records the verified response against replay, when the driver asks for it. */
        public ?ReplayRecord $replay = null,

        /** What lets the request finish across the key rotation its own validation made. */
        public ?TransitionReceipt $transitionReceipt = null,

        /** How the result's link resolved, as last asked. */
        public ?LinkResolution $resolution = null,

        /** The identity a reservation holds a link for; never a resolved identity. */
        public ?ReservedCandidate $reservedCandidate = null,

        /** The connection's claim of the linking email's domain, locked. */
        public ?Domain $linkingDomain = null,

        /** The linking policy version the response was validated under. */
        public ?int $linkingVersion = null,

        /** When the verified response stops being valid. */
        public ?CarbonImmutable $verifiedUntil = null,

        /** What plain reads found to lock before the locked transaction. */
        public ?LinkingDiscovery $linkingDiscovery = null,
    ) {}

    /**
     * What a dump shows: ids, and which parts are set, never what arrived, the
     * protocol state, the consumed request's secrets or the code.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'connection_id'       => $this->connectionId,
            'request_reference'   => $this->consumed?->reference->value,
            'application'         => $this->application?->name,
            'verified'            => $this->result         !== null,
            'linked'              => $this->linkedIdentity !== null,
            'enforcement_version' => $this->enforcementVersion,
            'handed_off'          => $this->handoff !== null,
            'resolution'          => $this->resolution?->status->value,
            'reserved'            => $this->reservedCandidate !== null,
        ];
    }

    /**
     * Refuse to be serialised: the state lives only for its completion.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A completion\'s state cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A completion\'s state cannot be unserialised.');
    }

    /**
     * The state of a completion that has just arrived at the connection's
     * endpoint.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return self
     */
    public static function arrived(string $connectionId, CompletionRequest $request): self
    {
        return new self($connectionId, $request);
    }

    /**
     * With the connection, read from the write connection, its claim of the
     * linking email's domain when that was locked with it, and what plain reads
     * found to lock before they were taken.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $linkingDomain
     * @param  ?\SineMacula\Laravel\Sso\Linking\LinkingDiscovery  $discovery
     * @return self
     */
    public function withConnection(?Connection $connection, ?Domain $linkingDomain = null, ?LinkingDiscovery $discovery = null): self
    {
        return $this->with(['connection' => $connection, 'linkingDomain' => $linkingDomain, 'linkingDiscovery' => $discovery]);
    }

    /**
     * With the correlation the driver read.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @return self
     */
    public function withCorrelation(Correlation $correlation): self
    {
        return $this->with(['correlation' => $correlation]);
    }

    /**
     * With the consumed authorisation request, what the driver is given of it
     * and its registered application.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @return self
     */
    public function withAuthorizationRequest(?AuthorizationRequest $request, ?ConsumedRequest $consumed, ?Application $application): self
    {
        return $this->with(['authorizationRequest' => $request, 'consumed' => $consumed, 'application' => $application]);
    }

    /**
     * With the enforcement policy judged from the rows the completion holds
     * locked, which the enforcement step judges the connection by.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @return self
     */
    public function withEnforcementPolicy(EnforcementPolicy $policy): self
    {
        return $this->with(['enforcementPolicy' => $policy]);
    }

    /**
     * With what the driver verified.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @return self
     */
    public function withClaims(VerifiedClaims $claims): self
    {
        return $this->with(['claims' => $claims]);
    }

    /**
     * With what records the verified response against replay.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ReplayRecord  $replay
     * @return self
     */
    public function withReplay(ReplayRecord $replay): self
    {
        return $this->with(['replay' => $replay]);
    }

    /**
     * With the receipt of the key rotation the response's own validation made.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @return self
     */
    public function withTransitionReceipt(TransitionReceipt $receipt): self
    {
        return $this->with(['transitionReceipt' => $receipt]);
    }

    /**
     * With the verified result.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return self
     */
    public function withResult(VerifiedResult $result): self
    {
        return $this->with(['result' => $result]);
    }

    /**
     * With how the result's link resolved, as last asked: the identity it
     * resolved to replaces any earlier one, and a resolution that resolves
     * nothing clears it; and with the candidate a reservation holds a link for,
     * if any, which is never the resolved identity.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @param  ?\SineMacula\Laravel\Sso\Links\ReservedCandidate  $candidate
     * @return self
     */
    public function withResolution(LinkResolution $resolution, ?ReservedCandidate $candidate = null): self
    {
        return $this->with(['resolution' => $resolution, 'linkedIdentity' => $resolution->identity, 'reservedCandidate' => $candidate]);
    }

    /**
     * With what the validation was based on: the linking policy version, and
     * when the verified response stops being valid.
     *
     * @param  int  $linkingVersion
     * @param  \Carbon\CarbonImmutable  $verifiedUntil
     * @return self
     */
    public function withValidation(int $linkingVersion, CarbonImmutable $verifiedUntil): self
    {
        return $this->with(['linkingVersion' => $linkingVersion, 'verifiedUntil' => $verifiedUntil]);
    }

    /**
     * With the enforcement version the completion checked.
     *
     * @param  string  $version
     * @return self
     */
    public function withEnforcementVersion(string $version): self
    {
        return $this->with(['enforcementVersion' => $version]);
    }

    /**
     * With the latest end of the application's session the provider's deadline
     * sets.
     *
     * @param  \Carbon\CarbonImmutable  $notAfter
     * @return self
     */
    public function withSessionNotAfter(CarbonImmutable $notAfter): self
    {
        return $this->with(['sessionNotAfter' => $notAfter]);
    }

    /**
     * With the handoff issued.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff  $handoff
     * @return self
     */
    public function withHandoff(IssuedHandoff $handoff): self
    {
        return $this->with(['handoff' => $handoff]);
    }

    /**
     * Whether a refusal can be redirected to the application: the request was
     * found and consumed, so its application and connection are trusted
     * (SSO-5.7). Before then there is no trusted target.
     *
     * @return bool
     */
    public function hasRedirectTarget(): bool
    {
        return $this->authorizationRequest !== null && $this->application !== null && $this->connection !== null;
    }

    /**
     * A new state with the parts given replaced and every other kept.
     *
     * @param  array<string, mixed>  $parts
     * @return self
     */
    private function with(array $parts): self
    {
        return new self(...[...get_object_vars($this), ...$parts]);
    }
}
