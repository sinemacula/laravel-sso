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
 * locks across exactly the key rotation its own refetch made.
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
     * Whether the receipt lets the request go on, the rows given as locked.
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
     * Whether the locked connection still admits the key the token verified
     * with for its algorithm; an allow-list that cannot be built admits none.
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
