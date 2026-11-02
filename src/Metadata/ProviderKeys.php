<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;

/**
 * The key an ID token's signature is checked with, from the JWKS stored with
 * its connection (SSO-7.3): chosen by exact `kid`, or by the missing-`kid`
 * rule, among the keys admitted again for the connection's allow-list
 * (`Protocols\Oidc\Jose\ProviderKeySet::select()`), read on the write
 * connection (SSO-11.3). It lives beside the refresh machinery, which writes
 * the JWKS it reads, since a protocol driver never reads a connection's row
 * itself.
 *
 * Only a selection that is unknown (a `kid` the stored JWKS does not hold, or
 * no `kid` and no admissible key) calls `JwksRefetcher`, once, and selects
 * again from what it leaves stored; a refused one (`none`, an HMAC, an
 * algorithm off the allow-list, two admissible keys with no `kid`) never
 * fetches, and a select never refetches twice or loops. A `kid` the refetch did
 * not bring stays unknown: it never falls back to a key without one. A caller
 * may first answer whether the token is already disqualified on its unverified
 * claims (`IdTokenValidator`): one that is stays unknown without touching the
 * shared cooldown, so a token that cannot pass never spends it.
 *
 * How each fetch ended is logged, through the sanitising logger, with its
 * reason and the fetch's status alone, never the URL, the body or a key. A
 * token the cooldown turns away logs nothing and fetches nothing: the refetcher
 * counts it, and the next claim of the cooldown, at most one per connection per
 * window across servers, logs how many were turned away since the last,
 * `sso.oidc.jwks_refetch_suppressed`, with the count alone.
 *
 * A connection gone, or a trust change found after a failed claim of the
 * cooldown or a compare and set lost (its trust version raised since it was
 * read), that leaves no key for the token is `overtaken`, so the completion
 * answers `connection_unavailable` rather than blaming the token's signature. A
 * refetch that lost to a change that is not one of trust stays unknown.
 *
 * A key found by a refetch that removed a key, for the consumed request whose
 * token asked, carries the `Protocols\TransitionReceipt` that lets that one
 * request finish across the trust change, naming the key it found
 * (`TransitionReceipts`).
 *
 * `resetFor()` is what an update of the connection's `issuer` or `jwks_uri`
 * clears in its locked transaction, so keys fetched for another issuer or URL
 * are never used (SSO-2.13), and what saving an endpoint by hand with the
 * connection's refresh off clears: from then on it follows no document, and has
 * no document's deadline.
 *
 * It holds the refetcher and the logger, neither of which keeps anything of one
 * call for the next (SSO-11.2). It is not final, so a test of the flow around
 * it can observe and answer its calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 *
 * @phpstan-import-type JwksRefetch from \SineMacula\Laravel\Sso\Metadata\JwksRefetcher
 */
readonly class ProviderKeys
{
    /** @var list<string> The endpoints an administrator may save by hand in place of a document's. */
    private const array ENDPOINTS = ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint'];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\JwksRefetcher  $refetcher
     * @param  \Psr\Log\LoggerInterface  $logger
     */
    public function __construct(

        /** Refetches the JWKS on a key it does not hold. */
        private JwksRefetcher $refetcher,

        /** The sanitising logger each refetch is logged to. */
        private LoggerInterface $logger,
    ) {}

    /**
     * What an update changing the settings named, to the stored settings given,
     * must also write to the locked connection: nothing for a protocol but OIDC
     * or for other settings. A change of the `issuer` or the `jwks_uri` clears
     * the stored keys, raises their version and clears the cooldown and the
     * refetch's token; a change of the `issuer` also clears when the discovery
     * document was last validated, until when and when it next refreshes. An
     * endpoint changed with the connection's `metadata_refresh` off clears when
     * the document was last validated and until when, since the administrator
     * has taken the endpoints over: turning the refresh off alone clears
     * nothing, so it never means unlimited trust.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  list<string>  $changedSettings
     * @param  array<string, mixed>  $stored
     * @return array<string, mixed>
     */
    public static function resetFor(Connection $locked, array $changedSettings, array $stored): array
    {
        if ($locked->protocol !== OidcDriver::NAME) {
            return [];
        }

        $issuer   = in_array(OidcSetting::ISSUER->value, $changedSettings, true);
        $moved    = array_intersect(self::ENDPOINTS, $changedSettings)                !== [];
        $byHand   = $moved && ($stored[OidcSetting::METADATA_REFRESH->value] ?? null) !== true;
        $document = ['metadata_fetched_at' => null, 'metadata_valid_until' => null];

        return [
            ...($issuer || in_array(OidcSetting::JWKS_URI->value, $changedSettings, true) ? self::keysReset($locked) : []),
            ...($issuer ? [...$document, 'metadata_refresh_at' => null] : []),
            ...($byHand ? $document : []),
        ];
    }

    /**
     * The key for the token among the connection's stored keys, the JWKS
     * refetched once when none is the token's, unless the closure given says
     * the token is already disqualified. The consumed request, when given, is
     * the one a key rotation the refetch makes spares.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  ?\Closure(): bool  $disqualified
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function select(
        SsoConnection $connection,
        CompactToken $token,
        AlgorithmAllowList $allowed,
        ?ConsumedRequest $consumed = null,
        ?\Closure $disqualified = null,
    ): KeySelection {
        $row = Connection::query()->useWritePdo()->whereKey($connection->getConnectionId())->first();

        if ($row === null) {
            return KeySelection::overtaken();
        }

        $selection = ProviderKeySet::fromStored($row->jwks, $allowed)->select($token, $allowed);

        if (!$selection->isUnknown() || ($disqualified !== null && $disqualified())) {
            return $selection;
        }

        return $this->refetched($row, $token, $allowed, $consumed);
    }

    /**
     * Refetch the JWKS and select again from what it leaves stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $row
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    private function refetched(Connection $row, CompactToken $token, AlgorithmAllowList $allowed, ?ConsumedRequest $consumed): KeySelection
    {
        $refetch = $this->refetcher->refetch($row, $allowed, $consumed?->reference);

        $this->logged($refetch);

        $selection = ProviderKeySet::fromStored($refetch['jwks'], $allowed)->select($token, $allowed);

        if (!$selection->isFound()) {
            return self::isOvertaken($row, $refetch) ? KeySelection::overtaken() : $selection;
        }

        $receipt = $refetch['receipt'];

        return $receipt === null ? $selection : $selection->withReceipt($receipt->withKey($selection->key->thumbprint(), $token->algorithm()));
    }

    /**
     * What clearing the locked connection's stored keys writes.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return array<string, mixed>
     */
    private static function keysReset(Connection $locked): array
    {
        return [
            'jwks'                    => null,
            'jwks_version'            => $locked->jwks_version + 1,
            'jwks_fetched_at'         => null,
            'jwks_refetch_at'         => null,
            'jwks_claim_token'        => null,
            'jwks_refetch_suppressed' => 0,
        ];
    }

    /**
     * Whether a trust change got there first: after a failed claim of the
     * cooldown or a compare and set lost, the connection as read is gone, or
     * its trust version has been raised since.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $read
     * @param  JwksRefetch  $refetch
     * @return bool
     */
    private static function isOvertaken(Connection $read, array $refetch): bool
    {
        $lost = in_array($refetch['outcome'], [JwksRefetcher::CONFLICT, JwksRefetcher::COOLING_DOWN], true);

        return $lost && $refetch['trust_version'] !== $read->trust_version;
    }

    /**
     * Log how the refetch ended, with its reason and the fetch's status alone:
     * a warning when it failed or lost to a change, information when it wrote,
     * and nothing when the cooldown turned the token away; then, at most once a
     * window, how many tokens the last window turned away.
     *
     * @param  JwksRefetch  $refetch
     * @return void
     */
    private function logged(array $refetch): void
    {
        if ($refetch['outcome'] === JwksRefetcher::COOLING_DOWN) {
            return;
        }

        $level = in_array($refetch['outcome'], [JwksRefetcher::FAILED, JwksRefetcher::CONFLICT], true) ? 'warning' : 'info';

        $this->logger->log($level, 'sso.oidc.jwks_refetch_' . $refetch['outcome'], ['reason' => $refetch['reason']?->value, 'fetch_status' => $refetch['fetch_status']?->value]);

        if ($refetch['suppressed'] === 0) {
            return;
        }

        $this->logger->info('sso.oidc.jwks_refetch_suppressed', ['suppressed' => $refetch['suppressed'], 'at_most' => JwksRefetcher::MAX_COUNTED_SUPPRESSED]);
    }
}
