<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Connection;
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
 * not bring stays unknown: it never falls back to a key without one. How each
 * refetch ended is logged, through the sanitising logger, with its reason and
 * the fetch's status alone, never the URL, the body or a key.
 *
 * A refetch that lost its compare and set to a trust change (the connection
 * gone, or its trust version raised since it was read) and left no key for the
 * token is `overtaken`, so the completion answers `connection_unavailable`
 * rather than blaming the token's signature. A refetch that lost to a change
 * that is not one of trust stays unknown.
 *
 * `resetFor()` is what an update of the connection's `issuer` or `jwks_uri`
 * clears in its locked transaction, so keys fetched for another issuer or URL
 * are never used (SSO-2.13).
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
     * What an update changing the settings named must also write to the locked
     * connection: nothing for a protocol but OIDC or for other settings. A
     * change of the `issuer` or the `jwks_uri` clears the stored keys, raises
     * their version and clears the cooldown and the refetch's token; a change
     * of the `issuer` also clears when the discovery document was last
     * validated, until when and when it next refreshes.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  list<string>  $changedSettings
     * @return array<string, mixed>
     */
    public static function resetFor(Connection $locked, array $changedSettings): array
    {
        $issuer = in_array(OidcSetting::ISSUER->value, $changedSettings, true);
        $keys   = $issuer || in_array(OidcSetting::JWKS_URI->value, $changedSettings, true);

        if (!$keys || $locked->protocol !== OidcDriver::NAME) {
            return [];
        }

        $reset = [
            'jwks'             => null,
            'jwks_version'     => $locked->jwks_version + 1,
            'jwks_fetched_at'  => null,
            'jwks_refetch_at'  => null,
            'jwks_claim_token' => null,
        ];

        return $issuer ? [...$reset, 'metadata_fetched_at' => null, 'metadata_valid_until' => null, 'metadata_refresh_at' => null] : $reset;
    }

    /**
     * The key for the token among the connection's stored keys, the JWKS
     * refetched once when none is the token's.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function select(SsoConnection $connection, CompactToken $token, AlgorithmAllowList $allowed): KeySelection
    {
        $row       = Connection::query()->useWritePdo()->whereKey($connection->getConnectionId())->first();
        $selection = ProviderKeySet::fromStored($row?->jwks, $allowed)->select($token, $allowed);

        if ($row === null || !$selection->isUnknown()) {
            return $selection;
        }

        $refetch = $this->refetcher->refetch($row, $allowed);

        $this->logged($refetch);

        $selection = ProviderKeySet::fromStored($refetch['jwks'], $allowed)->select($token, $allowed);

        return !$selection->isFound() && self::isOvertaken($row, $refetch) ? KeySelection::overtaken() : $selection;
    }

    /**
     * Whether the refetch lost to a trust change: the connection as read is
     * gone, or its trust version has been raised since.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $read
     * @param  JwksRefetch  $refetch
     * @return bool
     */
    private static function isOvertaken(Connection $read, array $refetch): bool
    {
        if ($refetch['outcome'] !== JwksRefetcher::CONFLICT) {
            return false;
        }

        return Connection::query()->useWritePdo()->whereKey($read->id)->first()?->trust_version !== $read->trust_version;
    }

    /**
     * Log how the refetch ended, with its reason and the fetch's status alone:
     * a warning when it failed or lost to a change, and information otherwise.
     *
     * @param  JwksRefetch  $refetch
     * @return void
     */
    private function logged(array $refetch): void
    {
        $level = in_array($refetch['outcome'], [JwksRefetcher::FAILED, JwksRefetcher::CONFLICT], true) ? 'warning' : 'info';

        $this->logger->log($level, 'sso.oidc.jwks_refetch_' . $refetch['outcome'], ['reason' => $refetch['reason']?->value, 'fetch_status' => $refetch['fetch_status']?->value]);
    }
}
