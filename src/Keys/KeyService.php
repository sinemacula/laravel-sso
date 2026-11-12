<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\CiphertextWrite;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\SamlRefreshRule;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;

/**
 * The management helpers of a connection's keys and trusted certificates.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-import-type CertificateFacts from \SineMacula\Laravel\Sso\Keys\CertificateInspector
 *
 * @phpstan-type Replacement array{
 *     added: list<\SineMacula\Laravel\Sso\Keys\KeySummary>,
 *     retired: list<\SineMacula\Laravel\Sso\Keys\KeySummary>,
 *     violations: list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
 * }
 */
final readonly class KeyService
{
    /** @var int The most identity provider certificates a connection trusts at once. */
    public const int MAX_TRUSTED_CERTIFICATES = 10;

    /** @var int The length of a key's id, a ULID. */
    private const int ID_LENGTH = 26;

    /** @var \SineMacula\Laravel\Sso\Connections\InFlightVoider Voids what a trust change leaves in flight. */
    private InFlightVoider $voider;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Keys\KeyGenerator  $generator
     * @param  \SineMacula\Laravel\Sso\Keys\CertificateInspector  $inspector
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     * @param  \SineMacula\Laravel\Sso\Keys\KeySettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $events
     * @param  \SineMacula\Laravel\Sso\Connections\InFlightVoider  $voider
     */
    public function __construct(

        /** Finds the tenant's connection, on the write connection. */
        private ConnectionFinder $connections,

        /** Asks the freshness contract before a change is written. */
        private FreshnessGate $freshness,

        /** Generates the service provider's own key pairs. */
        private KeyGenerator $generator,

        /** Reads and judges a certificate to trust. */
        private CertificateInspector $inspector,

        /** Encrypts a generated private key before it is written. */
        private SecretEncrypter $encrypter,

        /** The overlap a replaced key is kept for. */
        private KeySettings $settings,

        /** The clock the rotation times are read from. */
        private Clock $clock,

        /** Reports each change, inside its transaction. */
        private AdministrationEvents $events,

        // Assigned, not promoted, to keep its shape apart from DomainService's
        InFlightVoider $voider,
    ) {
        $this->voider = $voider;
    }

    /**
     * Generate a key pair of the use, RSA unless another type is given, and add
     * it as `next`, or `current` when the use has none.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    public function addNext(string $tenantId, string $connectionId, KeyUse $use, ClientContext $client, ?KeyType $type = null, ?Caller $caller = null): KeyResult
    {
        $type ??= KeyType::RSA;

        $connection = $this->additionPrechecked($tenantId, $connectionId, $use, $type, $caller);

        if ($connection instanceof KeyResult) {
            return $connection;
        }

        $generated = $this->generator->generate($type, $connection->id);
        $encrypted = $this->encrypter->encrypt($generated->privateKey->reveal());

        return $this->change($tenantId, $connectionId, fn (Connection $locked): KeyResult => $this->insertOwnKey($locked, $use, $generated, $encrypted, $caller, $client));
    }

    /**
     * Make the `next` key current; the current key of the use becomes
     * `retiring`, still decrypting until the overlap ends.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $keyId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function makeCurrent(string $tenantId, string $connectionId, string $keyId, ClientContext $client, ?Caller $caller = null): KeyResult
    {
        $overlap = $this->settings->overlapSeconds();

        return $this->keyChange(
            $tenantId,
            $connectionId,
            $keyId,
            $caller,
            static fn (): bool => true,
            static fn (ConnectionKey $key): bool => $key->use->isOwnKey() && $key->state === KeyState::NEXT,
            fn (Connection $locked, ConnectionKey $key): KeyResult => $this->promote($locked, $key, $overlap, $caller, $client),
        );
    }

    /**
     * Remove one of the connection's own keys that is `retiring` or `next`; the
     * current key is never retired.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $keyId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function retire(string $tenantId, string $connectionId, string $keyId, ClientContext $client, ?Caller $caller = null): KeyResult
    {
        return $this->keyChange(
            $tenantId,
            $connectionId,
            $keyId,
            $caller,
            static fn (): bool => true,
            static fn (ConnectionKey $key): bool => $key->use->isOwnKey() && in_array($key->state, [KeyState::NEXT, KeyState::RETIRING], true),
            fn (Connection $locked, ConnectionKey $key): KeyResult => KeyResult::retired($this->remove($locked, $key, $caller, $client)),
        );
    }

    /**
     * Trust a certificate for the SAML connection alongside those it trusts for
     * the use; only a metadata signing anchor voids what is in flight.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function trustCertificate(
        string $tenantId,
        string $connectionId,
        string $certificate,
        ClientContext $client,
        ?Caller $caller = null,
        KeyUse $use = KeyUse::IDP_SIGNING,
    ): KeyResult {
        $facts = $this->trustPrechecked($tenantId, $connectionId, $certificate, $use, $caller);

        if ($facts instanceof KeyResult) {
            return $facts;
        }

        return $this->change($tenantId, $connectionId, fn (Connection $locked): KeyResult => $this->insertTrusted($locked, $facts, $use, $caller, $client));
    }

    /**
     * Stop trusting one of the connection's certificates and void what is in
     * flight through it; removing the last one is allowed.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $keyId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function distrustCertificate(string $tenantId, string $connectionId, string $keyId, ClientContext $client, ?Caller $caller = null): KeyResult
    {
        return $this->keyChange(
            $tenantId,
            $connectionId,
            $keyId,
            $caller,
            static fn (ConnectionKey $key): bool => $key->use->isTrustedCertificate(),
            static fn (): bool => true,
            fn (Connection $locked, ConnectionKey $key): KeyResult => KeyResult::distrusted($this->remove($locked, $key, $caller, $client)),
        );
    }

    /**
     * Make the locked connection trust exactly the identity provider signing
     * certificates given, voiding what is in flight only when one is removed.
     * Call inside the transaction holding the connection's lock; it asks no
     * freshness.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  list<string>  $pems
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return Replacement
     *
     * @throws \LogicException
     *
     * @internal
     */
    public function replaceTrustedCertificatesLocked(Connection $locked, array $pems, ClientContext $client, ?Caller $caller = null): array
    {
        $wanted     = [];
        $violations = [];

        foreach ($pems as $index => $pem) {

            $inspected = $this->inspector->inspect($pem);
            $facts     = $inspected['facts'];
            $violation = $facts === null ? $inspected['violations'][0] : self::trustViolation($locked, $facts, KeyUse::IDP_SIGNING, true, array_keys($wanted));

            if ($violation !== null) {
                $violations[] = new SettingViolation(CertificateInspector::SETTING . '.' . $index, $violation->code);
            } elseif ($facts !== null) {
                $wanted[$facts['fingerprint']] = $facts;
            }
        }

        if ($violations !== []) {
            return ['added' => [], 'retired' => [], 'violations' => $violations];
        }

        $stored  = self::query($locked, true)->where('use', KeyUse::IDP_SIGNING->value)->get()->keyBy('fingerprint')->all();
        $retired = array_diff_key($stored, $wanted);

        foreach ($retired as $key) {
            $key->delete();
            $this->events->keyRetired($locked, $key, $caller, $client);
        }

        if ($retired !== []) {
            $this->voider->voidFor($locked);
        }

        $added = [];

        foreach (array_diff_key($wanted, $stored) as $facts) {
            $added[] = $this->insertTrusted($locked, $facts, KeyUse::IDP_SIGNING, $caller, $client)->key
                ?? throw new \LogicException('A judged certificate is trusted.');
        }

        return [
            'added'      => $added,
            'retired'    => array_values(array_map(KeySummary::of(...), $retired)),
            'violations' => [],
        ];
    }

    /**
     * Every key and certificate of the connection, by use, state and age;
     * `null` when the tenant has no such connection.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?list<\SineMacula\Laravel\Sso\Keys\KeySummary>
     *
     * @throws \InvalidArgumentException
     */
    public function keys(string $tenantId, string $connectionId): ?array
    {
        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return null;
        }

        $keys = self::query($connection)->get()->all();

        $rank = static fn (ConnectionKey $key): array => [
            array_search($key->use, KeyUse::cases(), true),
            array_search($key->state, [KeyState::CURRENT, KeyState::NEXT, KeyState::RETIRING, null], true),
            $key->created_at->getTimestamp(),
            $key->id,
        ];

        usort($keys, static fn (ConnectionKey $one, ConnectionKey $other): int => $rank($one) <=> $rank($other));

        return array_map(KeySummary::of(...), $keys);
    }

    /**
     * The connection a key pair of the use and type may be added to, or why
     * not.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult|\SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function additionPrechecked(string $tenantId, string $connectionId, KeyUse $use, KeyType $type, ?Caller $caller): Connection|KeyResult
    {
        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return KeyResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        $useAllowed  = $use->isOwnKey()                            && $use->protocol() === $connection->protocol;
        $typeAllowed = in_array($type, $use->allowedTypes(), true) && ClientAssertionKeys::fits($connection, $use, $type);
        $violations  = array_values(array_filter([
            $useAllowed ? null : new SettingViolation('use', ViolationCode::NOT_ALLOWED),
            $typeAllowed ? null : new SettingViolation('key_type', ViolationCode::NOT_ALLOWED),
        ], static fn (?SettingViolation $violation): bool => $violation !== null));

        return match (true) {
            $violations !== []                                                                                   => KeyResult::invalid($violations),
            self::query($connection)->where('use', $use->value)->where('state', KeyState::NEXT->value)->exists() => KeyResult::refused(FailureReason::KEY_STATE_CONFLICT),
            !$this->freshness->check($use->freshness(), $caller)->isFresh()                                      => KeyResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                                                              => $connection,
        };
    }

    /**
     * The facts of the certificate the connection may trust for the use, or why
     * not.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return CertificateFacts|\SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     */
    private function trustPrechecked(string $tenantId, string $connectionId, string $certificate, KeyUse $use, ?Caller $caller): array|KeyResult
    {
        if (!$use->isTrustedCertificate()) {
            throw new \InvalidArgumentException(sprintf('A certificate is trusted as [idp_signing] or [metadata_signing], never as [%s].', $use->value));
        }

        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return KeyResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        if ($connection->protocol !== $use->protocol()) {
            return KeyResult::invalid([new SettingViolation(CertificateInspector::SETTING, ViolationCode::UNSUPPORTED)]);
        }

        $inspected = $this->inspector->inspect($certificate);
        $facts     = $inspected['facts'];
        $violation = $facts === null ? null : self::trustViolation($connection, $facts, $use);

        return match (true) {
            $facts === null                                                 => KeyResult::invalid($inspected['violations']),
            $violation !== null                                             => KeyResult::invalid([$violation]),
            !$this->freshness->check($use->freshness(), $caller)->isFresh() => KeyResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                         => $facts,
        };
    }

    /**
     * Check the key and the caller's freshness, then check the key again under
     * the connection's lock and write.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $keyId
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\ConnectionKey): bool  $found
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\ConnectionKey): bool  $allowed
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection, \SineMacula\Laravel\Sso\Models\ConnectionKey): \SineMacula\Laravel\Sso\Keys\KeyResult  $write
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function keyChange(string $tenantId, string $connectionId, string $keyId, ?Caller $caller, \Closure $found, \Closure $allowed, \Closure $write): KeyResult
    {
        $connection = $this->connections->find($tenantId, $connectionId);
        $key        = $connection === null ? null : self::checkedKey(self::keyOf($connection, $keyId), $found, $allowed);

        $refusal = match (true) {
            $key === null                                                        => KeyResult::refused(FailureReason::CONNECTION_NOT_FOUND),
            $key instanceof KeyResult                                            => $key,
            !$this->freshness->check($key->use->freshness(), $caller)->isFresh() => KeyResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                              => null,
        };

        return $refusal ?? $this->change($tenantId, $connectionId, static function (Connection $locked) use ($keyId, $found, $allowed, $write): KeyResult {

            $key = self::checkedKey(self::keyOf($locked, $keyId, true), $found, $allowed);

            return $key instanceof KeyResult ? $key : $write($locked, $key);
        });
    }

    /**
     * Run the change in one transaction against the connection read again
     * locked for update.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection): \SineMacula\Laravel\Sso\Keys\KeyResult  $change
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function change(string $tenantId, string $connectionId, \Closure $change): KeyResult
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($tenantId, $connectionId, $change): KeyResult {

            $locked = $this->connections->findForUpdate($tenantId, $connectionId);

            return $locked === null ? KeyResult::refused(FailureReason::CONNECTION_NOT_FOUND) : $change($locked);
        });
    }

    /**
     * Insert the generated key pair as `current` when the use has none, else
     * `next`, unless a `next` key or the pinned algorithm changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\GeneratedKey  $generated
     * @param  string  $encrypted
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    private function insertOwnKey(
        Connection $locked,
        KeyUse $use,
        GeneratedKey $generated,
        #[\SensitiveParameter] string $encrypted,
        ?Caller $caller,
        ClientContext $client,
    ): KeyResult {
        if (!ClientAssertionKeys::fits($locked, $use, $generated->type)) {
            return KeyResult::invalid([new SettingViolation('key_type', ViolationCode::NOT_ALLOWED)]);
        }

        $states = self::query($locked, true)->where('use', $use->value)->whereNotNull('state')->toBase()->pluck('state')->all();

        if (in_array(KeyState::NEXT->value, $states, true)) {
            return KeyResult::refused(FailureReason::KEY_STATE_CONFLICT);
        }

        $first = !in_array(KeyState::CURRENT->value, $states, true);
        $key   = new ConnectionKey;

        $key->forceFill([
            'connection_id'   => $locked->id,
            'use'             => $use,
            'state'           => $first ? KeyState::CURRENT : KeyState::NEXT,
            'key_type'        => $generated->type,
            'key_bits'        => $generated->bits,
            'certificate'     => $generated->certificate,
            'public_key'      => $generated->publicKey,
            'private_key'     => $encrypted,
            'fingerprint'     => $generated->fingerprint,
            'not_before'      => $generated->notBefore,
            'not_after'       => $generated->notAfter,
            'made_current_at' => $first ? $this->clock->now() : null,
        ]);

        CiphertextWrite::save($key, 'private_key', 'The connection\'s key could not be written');

        $this->events->keyAdded($locked, $key, $caller, $client);

        if ($first) {
            $this->events->keyMadeCurrent($locked, $key, null, $caller, $client);
        }

        return KeyResult::added(KeySummary::of($key));
    }

    /**
     * Trust the certificate for the use, voiding what is in flight for a
     * metadata signing anchor, unless it was trusted or the cap reached
     * meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  CertificateFacts  $facts
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function insertTrusted(Connection $locked, array $facts, KeyUse $use, ?Caller $caller, ClientContext $client): KeyResult
    {
        $violation = self::trustViolation($locked, $facts, $use, true);

        if ($violation !== null) {
            return KeyResult::invalid([$violation]);
        }

        $anchor = $use === KeyUse::METADATA_SIGNING;
        $reset  = $anchor ? SamlRefreshRule::resetForAnchor($locked) : [];
        $key    = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $locked->id,
            'use'           => $use,
            'state'         => null,
            'key_type'      => $facts['type'],
            'key_bits'      => $facts['bits'],
            'certificate'   => $facts['certificate'],
            'public_key'    => $facts['public_key'],
            'private_key'   => null,
            'fingerprint'   => $facts['fingerprint'],
            'not_before'    => $facts['not_before'],
            'not_after'     => $facts['not_after'],
        ])->save();

        if ($anchor) {
            $locked->forceFill($reset)->save();
            $this->voider->voidFor($locked);
        }

        $this->events->keyAdded($locked, $key, $caller, $client);

        return KeyResult::trusted(KeySummary::of($key));
    }

    /**
     * Make the key current; the use's current key, if any, becomes `retiring`
     * until the overlap ends.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  int  $overlap
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     */
    private function promote(Connection $locked, ConnectionKey $key, int $overlap, ?Caller $caller, ClientContext $client): KeyResult
    {
        $now      = $this->clock->now();
        $previous = self::query($locked, true)->where('use', $key->use->value)->where('state', KeyState::CURRENT->value)->first();

        $previous?->forceFill(['state' => KeyState::RETIRING, 'retiring_until' => $now->addSeconds($overlap)])->save();

        $key->forceFill(['state' => KeyState::CURRENT, 'made_current_at' => $now, 'retiring_until' => null])->save();

        $this->events->keyMadeCurrent($locked, $key, $previous, $caller, $client);

        return KeyResult::madeCurrent(KeySummary::of($key), $previous === null ? null : KeySummary::of($previous));
    }

    /**
     * Delete the key and report it retired, answering it as it was; removing a
     * trusted certificate voids what is in flight.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     *
     * @throws \LogicException
     */
    private function remove(Connection $locked, ConnectionKey $key, ?Caller $caller, ClientContext $client): KeySummary
    {
        $summary = KeySummary::of($key);

        $key->delete();

        if ($key->use->freshness() === FreshnessOperation::CONNECTION_TRUST) {
            $this->voider->voidFor($locked);
        }

        $this->events->keyRetired($locked, $key, $caller, $client);

        return $summary;
    }

    /**
     * The key, when it is of the kind the change acts on and in a state the
     * change allows; else `key_not_found` or `key_state_conflict`.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\ConnectionKey): bool  $found
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\ConnectionKey): bool  $allowed
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult|\SineMacula\Laravel\Sso\Models\ConnectionKey
     *
     * @throws \InvalidArgumentException
     */
    private static function checkedKey(?ConnectionKey $key, \Closure $found, \Closure $allowed): ConnectionKey|KeyResult
    {
        return match (true) {
            $key === null || !$found($key) => KeyResult::refused(FailureReason::KEY_NOT_FOUND),
            !$allowed($key)                => KeyResult::refused(FailureReason::KEY_STATE_CONFLICT),
            default                        => $key,
        };
    }

    /**
     * What is wrong with trusting the certificate for the use, reading the
     * fingerprints trusted unless given.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  CertificateFacts  $facts
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  bool  $forUpdate
     * @param  ?list<string>  $trusted
     * @return ?\SineMacula\Laravel\Sso\Connections\SettingViolation
     *
     * @throws \InvalidArgumentException
     */
    private static function trustViolation(Connection $connection, array $facts, KeyUse $use, bool $forUpdate = false, ?array $trusted = null): ?SettingViolation
    {
        $trusted ??= self::query($connection, $forUpdate)->where('use', $use->value)->toBase()->pluck('fingerprint')->all();

        return match (true) {
            !in_array($facts['type'], $use->allowedTypes(), true) => new SettingViolation(CertificateInspector::SETTING, ViolationCode::UNSUPPORTED),
            in_array($facts['fingerprint'], $trusted, true)       => new SettingViolation(CertificateInspector::SETTING, ViolationCode::DUPLICATE),
            count($trusted) >= self::MAX_TRUSTED_CERTIFICATES     => new SettingViolation(CertificateInspector::SETTING, ViolationCode::TOO_MANY),
            default                                               => null,
        };
    }

    /**
     * The connection's key or certificate with the id, or `null`; an id that
     * cannot be a key's finds nothing without a query.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $keyId
     * @param  bool  $forUpdate
     * @return ?\SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private static function keyOf(Connection $connection, string $keyId, bool $forUpdate = false): ?ConnectionKey
    {
        if ($keyId === '' || strlen($keyId) > self::ID_LENGTH) {
            return null;
        }

        return self::query($connection, $forUpdate)->whereKey($keyId)->first();
    }

    /**
     * A query of the connection's keys on the write connection; under its lock,
     * read locked so a caller's older snapshot cannot answer.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  bool  $forUpdate
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\ConnectionKey>
     */
    private static function query(Connection $connection, bool $forUpdate = false): Builder
    {
        $query = ConnectionKey::query()->useWritePdo()->where('connection_id', $connection->id);

        return $forUpdate ? $query->lockForUpdate() : $query;
    }
}
