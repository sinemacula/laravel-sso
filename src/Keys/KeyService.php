<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\CiphertextWrite;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;

/**
 * The management helpers of a connection's keys and certificates (SSO-2.5 to
 * SSO-2.7, SSO-2.11, SSO-2.12): generate a key pair of the service provider's
 * own and add it as `next`, make it current, retire the key it replaced; trust
 * a signing certificate of the identity provider, and remove one.
 *
 * Each change is scoped to a tenant (a connection of another tenant is
 * `connection_not_found`, exactly as an unknown one), and goes in a fixed
 * order: find the connection and the key on the write connection; validate what
 * was given; check the key's state; ask the freshness contract
 * (`sso.keys.rotate` for a key of the service provider's own,
 * `sso.connection.trust` for a trusted certificate); generate the key, when one
 * is added; then, in one transaction on the storage connection, read the
 * connection again locked for update (which serialises a connection's
 * rotations), check the state again, write, and report through
 * `Administration\AdministrationEvents`. A state that changed in between is
 * `key_state_conflict`. A refusal at any step writes nothing and reports
 * nothing.
 *
 * A private key is encrypted through `Contracts\SecretEncrypter` before it is
 * written, and never returned: a result carries `Keys\KeySummary` values only
 * (SSO-2.5). A failed write of it is a `RuntimeException` that quotes nothing
 * of the ciphertext. A trusted certificate's dates are reported, never
 * enforced: an expired certificate is trusted (SSO-2.6).
 *
 * A trust change does not yet void the requests and codes in flight through the
 * connection; BL-37 adds that at every `sso.connection.trust` call site.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-import-type CertificateFacts from \SineMacula\Laravel\Sso\Keys\CertificateInspector
 */
final readonly class KeyService
{
    /** @var int The most identity provider certificates a connection trusts at once. */
    public const int MAX_TRUSTED_CERTIFICATES = 10;

    /** @var int The length of a key's id, a ULID. */
    private const int ID_LENGTH = 26;

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
    ) {}

    /**
     * Generate a key pair of the use and add it to the connection: as `next`,
     * or as `current` when the connection has no current key of the use. RSA
     * unless another type is given.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    public function addNext(string $tenantId, string $connectionId, KeyUse $use, ?KeyType $type = null, ?ActingIdentity $actor = null): KeyResult
    {
        $type ??= KeyType::RSA;

        $connection = $this->additionPrechecked($tenantId, $connectionId, $use, $type);

        if ($connection instanceof KeyResult) {
            return $connection;
        }

        $generated = $this->generator->generate($type, $connection->id);
        $encrypted = $this->encrypter->encrypt($generated->privateKey->reveal());

        return $this->change($tenantId, $connectionId, fn (Connection $locked): KeyResult => $this->insertOwnKey($locked, $use, $generated, $encrypted, $actor));
    }

    /**
     * Make the connection's `next` key current. The current key of the same use
     * becomes `retiring`, accepted for decryption until the overlap ends.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $keyId
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function makeCurrent(string $tenantId, string $connectionId, string $keyId, ?ActingIdentity $actor = null): KeyResult
    {
        $overlap = $this->settings->overlapSeconds();

        return $this->keyChange(
            $tenantId,
            $connectionId,
            $keyId,
            static fn (): bool => true,
            static fn (ConnectionKey $key): bool => $key->use->isOwnKey() && $key->state === KeyState::NEXT,
            fn (Connection $locked, ConnectionKey $key): KeyResult => $this->promote($locked, $key, $overlap, $actor),
        );
    }

    /**
     * Retire and remove one of the connection's own keys that is `retiring`, or
     * `next` and never made current. The current key is never retired, and a
     * trusted certificate is removed by `distrustCertificate()`.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $keyId
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function retire(string $tenantId, string $connectionId, string $keyId, ?ActingIdentity $actor = null): KeyResult
    {
        return $this->keyChange(
            $tenantId,
            $connectionId,
            $keyId,
            static fn (): bool => true,
            static fn (ConnectionKey $key): bool => $key->use->isOwnKey() && in_array($key->state, [KeyState::NEXT, KeyState::RETIRING], true),
            fn (Connection $locked, ConnectionKey $key): KeyResult => KeyResult::retired($this->remove($locked, $key, $actor)),
        );
    }

    /**
     * Trust a signing certificate of the identity provider for the SAML
     * connection, alongside those it already trusts. An expired certificate is
     * trusted: its dates are reported, never enforced.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $certificate
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function trustCertificate(string $tenantId, string $connectionId, string $certificate, ?ActingIdentity $actor = null): KeyResult
    {
        $facts = $this->trustPrechecked($tenantId, $connectionId, $certificate);

        if ($facts instanceof KeyResult) {
            return $facts;
        }

        return $this->change($tenantId, $connectionId, fn (Connection $locked): KeyResult => $this->insertTrusted($locked, $facts, $actor));
    }

    /**
     * Stop trusting one of the connection's identity provider certificates and
     * remove it. Removing the last one is allowed; the connection is then
     * incomplete until another is trusted.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $keyId
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function distrustCertificate(string $tenantId, string $connectionId, string $keyId, ?ActingIdentity $actor = null): KeyResult
    {
        return $this->keyChange(
            $tenantId,
            $connectionId,
            $keyId,
            static fn (ConnectionKey $key): bool => $key->use === KeyUse::IDP_SIGNING,
            static fn (): bool => true,
            fn (Connection $locked, ConnectionKey $key): KeyResult => KeyResult::distrusted($this->remove($locked, $key, $actor)),
        );
    }

    /**
     * Every key and certificate of the connection, by use, then by state
     * (current, next, retiring, then a trusted certificate's none), then oldest
     * first; `null` when the tenant has no such connection.
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
            match ($key->state) {
                KeyState::CURRENT  => 0,
                KeyState::NEXT     => 1,
                KeyState::RETIRING => 2,
                null               => 3,
            },
            $key->created_at->getTimestamp(),
            $key->id,
        ];

        usort($keys, static fn (ConnectionKey $one, ConnectionKey $other): int => $rank($one) <=> $rank($other));

        return array_map(KeySummary::of(...), $keys);
    }

    /**
     * The connection a key pair of the use and type may be added to, or why
     * not: no such connection, a use or type it does not allow, a `next` key of
     * the use already, or a caller who is not fresh enough.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult|\SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function additionPrechecked(string $tenantId, string $connectionId, KeyUse $use, KeyType $type): Connection|KeyResult
    {
        $connection = $this->connections->find($tenantId, $connectionId);
        $violations = $connection === null ? [] : self::ownKeyViolations($connection, $use, $type);

        return match (true) {
            $connection === null                                                                                 => KeyResult::refused(FailureReason::CONNECTION_NOT_FOUND),
            $violations !== []                                                                                   => KeyResult::invalid($violations),
            self::query($connection)->where('use', $use->value)->where('state', KeyState::NEXT->value)->exists() => KeyResult::refused(FailureReason::KEY_STATE_CONFLICT),
            !$this->freshness->check($use->freshness())->isFresh()                                               => KeyResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                                                              => $connection,
        };
    }

    /**
     * The facts of the certificate the connection may trust, or why not: no
     * such connection, not a SAML connection, a certificate refused by the
     * inspector, one it already trusts or one too many, or a caller who is not
     * fresh enough.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $certificate
     * @return CertificateFacts|\SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     */
    private function trustPrechecked(string $tenantId, string $connectionId, string $certificate): array|KeyResult
    {
        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return KeyResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        if ($connection->protocol !== KeyUse::IDP_SIGNING->protocol()) {
            return KeyResult::invalid([new SettingViolation(CertificateInspector::SETTING, ViolationCode::UNSUPPORTED)]);
        }

        $inspected = $this->inspector->inspect($certificate);
        $facts     = $inspected['facts'];
        $violation = $facts === null ? null : self::trustViolation($connection, $facts['fingerprint']);

        return match (true) {
            $facts === null                                                       => KeyResult::invalid($inspected['violations']),
            $violation !== null                                                   => KeyResult::invalid([$violation]),
            !$this->freshness->check(KeyUse::IDP_SIGNING->freshness())->isFresh() => KeyResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                               => $facts,
        };
    }

    /**
     * Change one of the connection's keys: find it, check it is of the kind the
     * change acts on and in a state the change allows, ask the freshness
     * contract, then find and check it again under the connection's lock and
     * write.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $keyId
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\ConnectionKey): bool  $found
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\ConnectionKey): bool  $allowed
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection, \SineMacula\Laravel\Sso\Models\ConnectionKey): \SineMacula\Laravel\Sso\Keys\KeyResult  $write
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function keyChange(string $tenantId, string $connectionId, string $keyId, \Closure $found, \Closure $allowed, \Closure $write): KeyResult
    {
        $connection = $this->connections->find($tenantId, $connectionId);
        $key        = $connection === null ? null : self::checkedKey(self::keyOf($connection, $keyId), $found, $allowed);

        $refusal = match (true) {
            $key === null                                               => KeyResult::refused(FailureReason::CONNECTION_NOT_FOUND),
            $key instanceof KeyResult                                   => $key,
            !$this->freshness->check($key->use->freshness())->isFresh() => KeyResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                     => null,
        };

        return $refusal ?? $this->change($tenantId, $connectionId, static function (Connection $locked) use ($keyId, $found, $allowed, $write): KeyResult {

            $key = self::checkedKey(self::keyOf($locked, $keyId, true), $found, $allowed);

            return $key instanceof KeyResult ? $key : $write($locked, $key);
        });
    }

    /**
     * Run the change in one transaction on the storage connection, against the
     * connection read again locked for update.
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
     * Insert the generated key pair for the locked connection: `current` when
     * it has no current key of the use, else `next`; refused when a `next` key
     * of the use was added meanwhile. A failed insert propagates as a
     * `RuntimeException` that quotes nothing of the encrypted private key.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\GeneratedKey  $generated
     * @param  string  $encrypted
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    private function insertOwnKey(Connection $locked, KeyUse $use, GeneratedKey $generated, #[\SensitiveParameter] string $encrypted, ?ActingIdentity $actor): KeyResult
    {
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

        $this->events->keyAdded($locked, $key, $actor);

        if ($first) {
            $this->events->keyMadeCurrent($locked, $key, null, $actor);
        }

        return KeyResult::added(KeySummary::of($key));
    }

    /**
     * Insert the inspected certificate as one the locked connection trusts;
     * refused when it was trusted, or the cap reached, meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  CertificateFacts  $facts
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \InvalidArgumentException
     */
    private function insertTrusted(Connection $locked, array $facts, ?ActingIdentity $actor): KeyResult
    {
        $violation = self::trustViolation($locked, $facts['fingerprint'], true);

        if ($violation !== null) {
            return KeyResult::invalid([$violation]);
        }

        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $locked->id,
            'use'           => KeyUse::IDP_SIGNING,
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

        $this->events->keyAdded($locked, $key, $actor);

        return KeyResult::trusted(KeySummary::of($key));
    }

    /**
     * Make the key current for the locked connection; its current key of the
     * same use, if any, becomes `retiring` until the overlap ends.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  int  $overlap
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     */
    private function promote(Connection $locked, ConnectionKey $key, int $overlap, ?ActingIdentity $actor): KeyResult
    {
        $now      = $this->clock->now();
        $previous = self::query($locked, true)->where('use', $key->use->value)->where('state', KeyState::CURRENT->value)->first();

        $previous?->forceFill(['state' => KeyState::RETIRING, 'retiring_until' => $now->addSeconds($overlap)])->save();

        $key->forceFill(['state' => KeyState::CURRENT, 'made_current_at' => $now, 'retiring_until' => null])->save();

        $this->events->keyMadeCurrent($locked, $key, $previous, $actor);

        return KeyResult::madeCurrent(KeySummary::of($key), $previous === null ? null : KeySummary::of($previous));
    }

    /**
     * Delete the locked connection's key and report it retired, answering the
     * key as it was before.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function remove(Connection $locked, ConnectionKey $key, ?ActingIdentity $actor): KeySummary
    {
        $summary = KeySummary::of($key);

        $key->delete();

        $this->events->keyRetired($locked, $key, $actor);

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
     * What is wrong with adding a key pair of the use and type to the
     * connection: a trusted certificate's use, or a use of another protocol,
     * and a type the use does not allow.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     *
     * @throws \InvalidArgumentException
     */
    private static function ownKeyViolations(Connection $connection, KeyUse $use, KeyType $type): array
    {
        $violations = [];

        if (!$use->isOwnKey() || $use->protocol() !== $connection->protocol) {
            $violations[] = new SettingViolation('use', ViolationCode::NOT_ALLOWED);
        }

        if (!in_array($type, $use->allowedTypes(), true)) {
            $violations[] = new SettingViolation('key_type', ViolationCode::NOT_ALLOWED);
        }

        return $violations;
    }

    /**
     * What is wrong with trusting a certificate of the fingerprint for the
     * connection: one it already trusts, or one more than it may.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $fingerprint
     * @param  bool  $forUpdate
     * @return ?\SineMacula\Laravel\Sso\Connections\SettingViolation
     *
     * @throws \InvalidArgumentException
     */
    private static function trustViolation(Connection $connection, string $fingerprint, bool $forUpdate = false): ?SettingViolation
    {
        $trusted = self::query($connection, $forUpdate)->where('use', KeyUse::IDP_SIGNING->value)->toBase()->pluck('fingerprint')->all();

        return match (true) {
            in_array($fingerprint, $trusted, true)            => new SettingViolation(CertificateInspector::SETTING, ViolationCode::DUPLICATE),
            count($trusted) >= self::MAX_TRUSTED_CERTIFICATES => new SettingViolation(CertificateInspector::SETTING, ViolationCode::TOO_MANY),
            default                                           => null,
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
     * A query of the connection's keys and certificates, on the write
     * connection.
     *
     * Every read made under the connection's lock locks what it reads too. A
     * plain read there would answer from the snapshot of a transaction the
     * caller opened (MySQL's `REPEATABLE READ`), which may predate a change
     * committed before the lock was taken; a locking read always sees the
     * latest committed rows.
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
