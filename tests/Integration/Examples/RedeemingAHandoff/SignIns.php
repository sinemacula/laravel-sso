<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The application's own sign-ins of `docs/guides/redeeming-a-handoff.md`
 * (SSO-9.2, SSO-12.5): the session an admitted `sign_in` establishes, written
 * inside the redemption's transaction and bound to the link the identity
 * resolved through, and the token that leaves only once that transaction has
 * committed.
 *
 * It keeps its sessions and the digests of its tokens in memory, which is all a
 * test needs; an application writes its sessions to its own table through the
 * package's storage connection, so they commit with the redemption.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignIns
{
    /** @var array<string, array{identity: \SineMacula\Laravel\Sso\Identities\IdentityReference, link: string}> Each session, by its id. */
    private array $sessions = [];

    /** @var array<string, string> The session each token is for, by the token's SHA-256 digest. */
    private array $tokens = [];

    /**
     * Write the session of the identity, bound to the link it resolved through,
     * inside the redemption's transaction, and answer its id.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @return string
     *
     * @throws \LogicException
     */
    public function start(IdentityReference $identity, string $linkId): string
    {
        if (self::transactionLevel() === 0) {
            throw new \LogicException('A session is written inside the redemption\'s transaction.');
        }

        $sessionId = strtolower((string) Str::ulid());

        $this->sessions[$sessionId] = ['identity' => $identity, 'link' => $linkId];

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
     * The session a token is for, or `null`.
     *
     * @param  string  $token
     * @return ?string
     */
    public function sessionOf(#[\SensitiveParameter] string $token): ?string
    {
        return $this->tokens[hash('sha256', $token)] ?? null;
    }

    /**
     * The identity the session signed in, or `null` when there is no such
     * session.
     *
     * @param  string  $sessionId
     * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    public function identityOf(string $sessionId): ?IdentityReference
    {
        return ($this->sessions[$sessionId] ?? null)['identity'] ?? null;
    }

    /**
     * The link the session is bound to, or `null` when there is no such
     * session.
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
