<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;

/**
 * Whether a `Protocols\TransitionReceipt` lets a request go on at the final
 * locks though its trust version is no longer its connection's (SSO-2.13,
 * SSO-7.3). `permits()` is asked with the rows as those locking reads gave
 * them, and needs every one of these:
 *
 * - the receipt names exactly this connection and this request;
 * - the request is still consumed, not finished and not voided, so a request
 *   voided by anything is never restored;
 * - the request's trust version is the one the receipt left, and the
 *   connection's the one the receipt made, not a later one, so any independent
 *   trust change since the refetch (a second rotation, a distrust, a disable,
 *   an enable, a setting) refuses the completion;
 * - the connection's JWKS version is the one the receipt wrote, so a refresh or
 *   another write of the keys since refuses it too;
 * - the key the token verified with is still admitted, under the connection's
 *   allow-list as locked, for the algorithm it verified under.
 *
 * Whether the metadata is still fresh is the completion's own next check, under
 * the same locks (`MetadataExpiry`), so an expired connection is refused
 * `metadata_expired` here as anywhere.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TransitionReceipts
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the receipt lets the request go on across exactly the transition
     * it names, the rows given as they are locked.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return bool
     */
    public static function permits(?TransitionReceipt $receipt, Connection $locked, AuthorizationRequest $request): bool
    {
        if ($receipt === null || !self::namesExactly($receipt, $locked, $request)) {
            return false;
        }

        return self::isUnfinished($request) && self::admitsKey($receipt, $locked);
    }

    /**
     * Whether the receipt names this connection, this request and the versions
     * each holds now.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return bool
     */
    private static function namesExactly(TransitionReceipt $receipt, Connection $locked, AuthorizationRequest $request): bool
    {
        $expected = [$receipt->connectionId, $receipt->requestId, $receipt->fromTrustVersion, $receipt->toTrustVersion, $receipt->jwksVersion];

        return $expected === [$locked->id, $request->id, $request->trust_version, $locked->trust_version, $locked->jwks_version];
    }

    /**
     * Whether the request is consumed, not finished and not voided.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return bool
     */
    private static function isUnfinished(AuthorizationRequest $request): bool
    {
        return $request->consumed_at !== null && $request->completed_at === null && $request->voided_at === null;
    }

    /**
     * Whether the key the token verified with is still admitted for the
     * algorithm it verified under, by the locked connection's allow-list; an
     * allow-list that cannot be built admits nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return bool
     */
    private static function admitsKey(TransitionReceipt $receipt, Connection $locked): bool
    {
        try {
            $allowed = OidcOptions::of($locked)->algorithms();
        } catch (\InvalidArgumentException) {
            return false;
        }

        foreach (ProviderKeySet::fromStored($locked->jwks, $allowed)->keys as $key) {
            if ($key->thumbprint() === $receipt->keyThumbprint() && $key->fits((string) $receipt->algorithm, $allowed)) {
                return true;
            }
        }

        return false;
    }
}
