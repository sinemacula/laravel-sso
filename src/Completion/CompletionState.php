<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Http\ClientContext;
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
 * What a completion has established so far, handed from each stage to the next.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type Parts array{
 *     connection?: ?\SineMacula\Laravel\Sso\Models\Connection,
 *     correlation?: ?\SineMacula\Laravel\Sso\Protocols\Correlation,
 *     authorizationRequest?: ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest,
 *     consumed?: ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest,
 *     application?: ?\SineMacula\Laravel\Sso\Applications\Application,
 *     enforcementPolicy?: ?\SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy,
 *     claims?: ?\SineMacula\Laravel\Sso\Results\VerifiedClaims,
 *     result?: ?\SineMacula\Laravel\Sso\Results\VerifiedResult,
 *     linkedIdentity?: ?\SineMacula\Laravel\Sso\Identities\IdentityReference,
 *     sessionNotAfter?: ?\Carbon\CarbonImmutable,
 *     handoff?: ?\SineMacula\Laravel\Sso\Handoffs\IssuedHandoff,
 *     replay?: ?\SineMacula\Laravel\Sso\Protocols\ReplayRecord,
 *     transitionReceipt?: ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt,
 *     resolution?: ?\SineMacula\Laravel\Sso\Links\LinkResolution,
 *     reservedCandidate?: ?\SineMacula\Laravel\Sso\Links\ReservedCandidate,
 *     linkingDomain?: ?\SineMacula\Laravel\Sso\Models\Domain,
 *     linkingVersion?: ?int,
 *     verifiedUntil?: ?\Carbon\CarbonImmutable,
 *     linkingDiscovery?: ?\SineMacula\Laravel\Sso\Linking\LinkingDiscovery
 * }
 */
final readonly class CompletionState
{
    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  ?\SineMacula\Laravel\Sso\Models\AuthorizationRequest  $authorizationRequest
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $enforcementPolicy
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
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

        /** The connection id the application's route gave. */
        public string $connectionId,

        /** What arrived at the endpoint. */
        public CompletionRequest $request,

        /** The client the response arrived from. */
        public ClientContext $client,

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

        /** The enforcement policy from the locked rows, when the default contract locked them. */
        public ?EnforcementPolicy $enforcementPolicy = null,

        /** What the driver verified. */
        public ?VerifiedClaims $claims = null,

        /** The verified result built from the claims. */
        public ?VerifiedResult $result = null,

        /** The identity the result's link resolved to, if any. */
        public ?IdentityReference $linkedIdentity = null,

        /** The session's latest end, set by the provider's deadline. */
        public ?CarbonImmutable $sessionNotAfter = null,

        /** The handoff issued. */
        public ?IssuedHandoff $handoff = null,

        /** What records the verified response against replay, if the driver asks. */
        public ?ReplayRecord $replay = null,

        /** Lets the request finish across a key rotation its own validation made. */
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
     * Dump only ids and which parts are set, never a secret.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'connection_id'     => $this->connectionId,
            'request_reference' => $this->consumed?->reference->value,
            'application'       => $this->application?->name,
            'verified'          => $this->result         !== null,
            'linked'            => $this->linkedIdentity !== null,
            'handed_off'        => $this->handoff        !== null,
            'resolution'        => $this->resolution?->status->value,
            'reserved'          => $this->reservedCandidate !== null,
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
     * The state of a completion that has just arrived.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return self
     */
    public static function arrived(string $connectionId, CompletionRequest $request, ClientContext $client): self
    {
        return new self($connectionId, $request, $client);
    }

    /**
     * With the connection, its locked linking domain and the linking discovery.
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
     * With the enforcement policy judged from the locked rows.
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
     * With how the link resolved, replacing or clearing the linked identity,
     * and any reserved candidate.
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
     * With the linking policy version validated under and the response's
     * validity.
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
     * With the session's latest end, set by the provider's deadline.
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
     * Whether a refusal can be redirected: the consumed request makes its
     * application and connection trusted.
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
     * @param  Parts  $parts
     * @return self
     */
    private function with(array $parts): self
    {
        return new self(...[
            'connectionId'         => $this->connectionId,
            'request'              => $this->request,
            'client'               => $this->client,
            'connection'           => $this->connection,
            'correlation'          => $this->correlation,
            'authorizationRequest' => $this->authorizationRequest,
            'consumed'             => $this->consumed,
            'application'          => $this->application,
            'enforcementPolicy'    => $this->enforcementPolicy,
            'claims'               => $this->claims,
            'result'               => $this->result,
            'linkedIdentity'       => $this->linkedIdentity,
            'sessionNotAfter'      => $this->sessionNotAfter,
            'handoff'              => $this->handoff,
            'replay'               => $this->replay,
            'transitionReceipt'    => $this->transitionReceipt,
            'resolution'           => $this->resolution,
            'reservedCandidate'    => $this->reservedCandidate,
            'linkingDomain'        => $this->linkingDomain,
            'linkingVersion'       => $this->linkingVersion,
            'verifiedUntil'        => $this->verifiedUntil,
            'linkingDiscovery'     => $this->linkingDiscovery,
            ...$parts,
        ]);
    }
}
