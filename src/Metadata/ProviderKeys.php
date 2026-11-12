<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;

/**
 * The key an ID token's signature is checked with, from the connection's stored
 * JWKS, refetched once when the token's key is unknown.
 *
 * Not final, so a test of the flow around it can observe and answer its calls.
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
     * What an update of the named settings must also write to the locked OIDC
     * connection, so keys and stamps of another issuer or URL are never used.
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
     * The key for the token among the stored keys, refetched once when none is
     * the token's unless the token is already disqualified.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
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
        ClientContext $client,
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

        return $this->refetched($row, $token, $allowed, $consumed, $client);
    }

    /**
     * Refetch the JWKS and select again from what it leaves stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $row
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    private function refetched(Connection $row, CompactToken $token, AlgorithmAllowList $allowed, ?ConsumedRequest $consumed, ClientContext $client): KeySelection
    {
        $refetch = $this->refetcher->refetch($row, $allowed, $client, $consumed?->reference);

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
     * Whether a trust change got there first, so the completion answers
     * `connection_unavailable` rather than blaming the token's signature.
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
     * Log how the refetch ended, nothing when the cooldown turned it away, then
     * how many tokens the last window turned away.
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
