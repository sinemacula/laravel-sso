<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Application;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;
use Tests\Integration\Examples\Application\ExampleSessions;

/**
 * The example application's sign-in sessions and their credentials. A session
 * is `pending` unless its further-factor policy passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignIns
{
    /** @var list<string> The RFC 8176 methods this application counts as its further factor. */
    public const array FURTHER_FACTOR_METHODS = ['hwk', 'mfa', 'otp', 'sc', 'swk'];

    /** @var array<string, true> Connections trusted for the further factor, by id. */
    private array $furtherFactorConnections = [];

    /** @var array<string, bool> Whether each session is pending, by its id. */
    private array $pending = [];

    /** @var array<string, string> The session each credential is for, by its SHA-256 digest. */
    private array $credentials = [];

    /** @var array<string, ?array<string, mixed>> Each session's provenance, by its id. */
    private array $provenance = [];

    /**
     * Keep the sessions in the store given, timed by the package's clock.
     *
     * @param  \Tests\Integration\Examples\Application\ExampleSessions  $sessions
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The sessions the re-authentication contract reads. */
        private readonly ExampleSessions $sessions,

        /** The clock a session with no provider time is timed by. */
        private readonly Clock $clock,
    ) {}

    /**
     * Write the session of an admitted `sign_in`, in the caller's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return string
     *
     * @throws \LogicException
     */
    public function start(RedemptionResult $redemption): string
    {
        $identity = $redemption->linkedIdentity;
        $result   = $redemption->result;
        $linkId   = $redemption->linkId;

        if (!$redemption->isAdmitted() || $identity === null) {
            throw new \LogicException('A session is written only for an admitted sign-in that resolved to an identity.');
        }

        if ($result === null || $linkId === null) {
            throw new \LogicException('An admitted sign-in carries its verified result and the link it resolved through.');
        }

        $sessionId       = (string) Str::ulid();
        $authenticatedAt = $result->authenticationContext->authenticatedAt ?? $this->clock->now();

        $this->sessions->establish($sessionId, $identity, $result->application, $result->connectionId, $linkId, $authenticatedAt);

        $this->pending[$sessionId] = !$this->satisfiesFurtherFactor($redemption);

        // @snippet-start route-provenance-capture
        // Written once, with the session, in the redemption's transaction;
        // never rewritten, not even by a re-authentication
        $this->provenance[$sessionId] = $redemption->provenance?->toArray();
        // @snippet-end route-provenance-capture
        return $sessionId;
    }

    /**
     * The session's `sso.*` context, empty for a session the package did not
     * establish.
     *
     * @param  string  $sessionId
     * @return array<string, mixed>
     *
     * @throws \UnexpectedValueException
     */
    public function context(string $sessionId): array
    {
        // @snippet-start route-provenance-project
        return AuthenticationContext::fromStored($this->provenance[$sessionId] ?? null);
        // @snippet-end route-provenance-project
    }

    /**
     * Trust the connection's accepted evidence for the further factor.
     *
     * @param  string  $connectionId
     * @return void
     */
    public function trustFurtherFactorFrom(string $connectionId): void
    {
        $this->furtherFactorConnections[$connectionId] = true;
    }

    /**
     * The credential for the session, once its transaction has committed.
     *
     * @param  string  $sessionId
     * @return array{status: string, token: string}
     *
     * @throws \LogicException
     */
    public function credential(string $sessionId): array
    {
        // Sent inside the transaction, it would outlive a rollback
        if (DB::connection(StorageConnection::name())->transactionLevel() !== 0) {
            throw new \LogicException('A credential is issued only once the session\'s transaction has committed.');
        }

        $token = Str::random(64);

        $this->credentials[hash('sha256', $token)] = $sessionId;

        return ['status' => ($this->pending[$sessionId] ?? true) ? 'pending' : 'active', 'token' => $token];
    }

    /**
     * The session a credential is for, or `null`.
     *
     * @param  string  $token
     * @return ?string
     */
    public function sessionOf(#[\SensitiveParameter] string $token): ?string
    {
        return $this->credentials[hash('sha256', $token)] ?? null;
    }

    /**
     * Whether the accepted evidence satisfies the further-factor policy.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return bool
     */
    private function satisfiesFurtherFactor(RedemptionResult $redemption): bool
    {
        // @snippet-start route-further-factor
        $evidence = $redemption->evidence;

        // Accepted evidence is an input to your own policy, never a pass: count
        // it only from a connection you trust for the further factor, and only
        // for a method you count as one
        if ($evidence === null || !isset($this->furtherFactorConnections[$evidence->connectionId])) {
            return false;
        }

        return array_intersect($evidence->methods(), self::FURTHER_FACTOR_METHODS) !== [];
        // @snippet-end route-further-factor
    }
}
