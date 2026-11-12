<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Sessions\Provenance;

/**
 * The application's own sessions and tokens, held in memory for the examples.
 * An application writes sessions through the package's storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignIns
{
    /** @var array<string, array{identity: \SineMacula\Laravel\Sso\Identities\IdentityReference, link: string, not_after: ?\Carbon\CarbonImmutable, provenance: ?\SineMacula\Laravel\Sso\Sessions\Provenance}> Each session, by its id. */
    private array $sessions = [];

    /** @var array<string, string> The session each token is for, by the token's SHA-256 digest. */
    private array $tokens = [];

    /**
     * Read the time from the package's clock.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock a session's latest end is enforced by. */
        private readonly Clock $clock,
    ) {}

    /**
     * Write the identity's session inside the redemption's transaction and
     * answer its id.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @param  ?\Carbon\CarbonImmutable  $notAfter
     * @param  ?\SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return string
     *
     * @throws \LogicException
     */
    public function start(IdentityReference $identity, string $linkId, ?CarbonImmutable $notAfter = null, ?Provenance $provenance = null): string
    {
        if (self::transactionLevel() === 0) {
            throw new \LogicException('A session is written inside the redemption\'s transaction.');
        }

        $sessionId = strtolower((string) Str::ulid());

        $this->sessions[$sessionId] = ['identity' => $identity, 'link' => $linkId, 'not_after' => $notAfter, 'provenance' => $provenance];

        return $sessionId;
    }

    /**
     * A token for the session, once its transaction has committed.
     *
     * @param  string  $sessionId
     * @return string
     *
     * @throws \LogicException
     */
    public function token(string $sessionId): string
    {
        // Sent inside the transaction, it would outlive a rollback
        if (self::transactionLevel() !== 0) {
            throw new \LogicException('A token is issued only once the session\'s transaction has committed.');
        }

        $token = Str::random(64);

        $this->tokens[hash('sha256', $token)] = $sessionId;

        return $token;
    }

    /**
     * The session a token is for, while it is active, or `null`.
     *
     * @param  string  $token
     * @return ?string
     */
    public function sessionOf(#[\SensitiveParameter] string $token): ?string
    {
        $sessionId = $this->tokens[hash('sha256', $token)] ?? null;

        return $sessionId !== null && $this->isActive($sessionId) ? $sessionId : null;
    }

    /**
     * Whether the session exists and has not reached its latest end.
     *
     * @param  string  $sessionId
     * @return bool
     */
    public function isActive(string $sessionId): bool
    {
        if (!array_key_exists($sessionId, $this->sessions)) {
            return false;
        }

        $notAfter = $this->sessions[$sessionId]['not_after'];

        return $notAfter === null || $this->clock->now()->lessThan($notAfter);
    }

    /**
     * The latest end of the session, or `null` when uncapped or unknown.
     *
     * @param  string  $sessionId
     * @return ?\Carbon\CarbonImmutable
     */
    public function notAfterOf(string $sessionId): ?CarbonImmutable
    {
        return ($this->sessions[$sessionId] ?? null)['not_after'] ?? null;
    }

    /**
     * How the session began, as its redemption captured it, or `null`.
     *
     * @param  string  $sessionId
     * @return ?\SineMacula\Laravel\Sso\Sessions\Provenance
     */
    public function provenanceOf(string $sessionId): ?Provenance
    {
        return ($this->sessions[$sessionId] ?? null)['provenance'] ?? null;
    }

    /**
     * The identity the session signed in, or `null`.
     *
     * @param  string  $sessionId
     * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    public function identityOf(string $sessionId): ?IdentityReference
    {
        return ($this->sessions[$sessionId] ?? null)['identity'] ?? null;
    }

    /**
     * The link the session is bound to, or `null`.
     *
     * @param  string  $sessionId
     * @return ?string
     */
    public function linkOf(string $sessionId): ?string
    {
        return ($this->sessions[$sessionId] ?? null)['link'] ?? null;
    }

    /**
     * The ids of the identity's sessions, oldest first.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return list<string>
     */
    public function sessionsOf(IdentityReference $identity): array
    {
        $held = array_filter($this->sessions, static fn (array $session): bool => $session['identity']->is($identity));

        return array_map(strval(...), array_keys($held));
    }

    /**
     * How deep the transactions open on the package's storage connection are.
     *
     * @return int
     */
    private static function transactionLevel(): int
    {
        return DB::connection(StorageConnection::name())->transactionLevel();
    }
}
