<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * A connection's secrets, stored as a JSON object of ciphertexts by name, each
 * encrypted on its own so a read can mask them without decrypting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConnectionSecrets
{
    /** @var int The longest secret, in bytes. */
    public const int MAX_LENGTH = 1024;

    /** @var string The refusal of a column that is not an object of ciphertexts. */
    private const string MALFORMED = 'The connection\'s stored secrets are not a JSON object of ciphertexts by name.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     */
    public function __construct(

        /** The encrypter every secret is encrypted and decrypted through. */
        private SecretEncrypter $encrypter,
    ) {}

    /**
     * The names of the secrets the connection has set.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return list<string>
     *
     * @throws \UnexpectedValueException
     */
    public function names(Connection $connection): array
    {
        return array_keys(self::decode($connection->secrets));
    }

    /**
     * Each declared secret masked: set or not, and nothing of it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  list<string>  $names
     * @return array<string, \SineMacula\Laravel\Sso\Secrets\MaskedSecret>
     *
     * @throws \UnexpectedValueException
     */
    public function masked(Connection $connection, array $names): array
    {
        $stored = self::decode($connection->secrets);
        $masked = [];

        foreach ($names as $name) {
            $masked[$name] = array_key_exists($name, $stored) ? MaskedSecret::set() : MaskedSecret::unset();
        }

        return $masked;
    }

    /**
     * The decrypted secret, or `null` when it is not set.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \UnexpectedValueException
     * @throws \RuntimeException
     */
    public function reveal(Connection $connection, string $name): ?Secret
    {
        $ciphertext = self::decode($connection->secrets)[$name] ?? null;

        if ($ciphertext === null) {
            return null;
        }

        return self::secret($this->encrypter->decrypt($ciphertext));
    }

    /**
     * Whether the secret is set, for a connection given through its contract;
     * `false` when the connection is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  string  $name
     * @return bool
     *
     * @throws \UnexpectedValueException
     */
    public function isSet(SsoConnection $connection, string $name): bool
    {
        $row = self::row($connection);

        return $row !== null && in_array($name, $this->names($row), true);
    }

    /**
     * The decrypted secret of a connection given through its contract; `null`
     * when it is not set or the connection is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \UnexpectedValueException
     * @throws \RuntimeException
     */
    public function revealFor(SsoConnection $connection, string $name): ?Secret
    {
        $row = self::row($connection);

        return $row === null ? null : $this->reveal($row, $name);
    }

    /**
     * The column after the changes, where `null` removes a secret; `null` when
     * none remains.
     *
     * @param  ?string  $stored
     * @param  array<string, ?\SineMacula\Laravel\Sso\Secrets\Secret>  $changes
     * @return ?string
     *
     * @throws \UnexpectedValueException
     * @throws \RuntimeException
     * @throws \JsonException
     */
    public function apply(?string $stored, array $changes): ?string
    {
        $secrets = self::decode($stored);

        foreach ($changes as $name => $secret) {

            if ($secret === null) {
                unset($secrets[$name]);
                continue;
            }

            $secrets[$name] = $this->encrypter->encrypt($secret->reveal());
        }

        return $secrets === [] ? null : json_encode($secrets, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * The problems with the secrets given, in declared order; a `null` secret
     * is a clear and never refused.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolSettings  $settings
     * @param  list<string>  $names
     * @param  array<string, mixed>  $given
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    public static function violations(ProtocolSettings $settings, array $names, #[\SensitiveParameter] array $given): array
    {
        $violations = [];

        foreach ($names as $name) {

            $secret = $given[$name] ?? null;

            if ($secret === null) {
                continue;
            }

            $code = SettingRules::text($secret, self::MAX_LENGTH) ?? (self::isUnsupported($settings, $name) ? ViolationCode::UNSUPPORTED : null);

            array_push($violations, ...SettingRules::at($name, $code));
        }

        return $violations;
    }

    /**
     * The names a change alters, in declared order; clearing an unset secret
     * alters nothing.
     *
     * @param  list<string>  $names
     * @param  array<string, mixed>  $given
     * @param  list<string>  $stored
     * @return list<string>
     */
    public static function changedNames(array $names, #[\SensitiveParameter] array $given, array $stored): array
    {
        return array_values(array_filter($names, static fn (string $name): bool => array_key_exists($name, $given) && ($given[$name] !== null || in_array($name, $stored, true))));
    }

    /**
     * The validated secrets given, as the changes `apply()` takes.
     *
     * @param  array<string, mixed>  $given
     * @return array<string, ?\SineMacula\Laravel\Sso\Secrets\Secret>
     *
     * @throws \InvalidArgumentException
     */
    public static function changes(#[\SensitiveParameter] array $given): array
    {
        return array_map(static fn (#[\SensitiveParameter] mixed $secret): ?Secret => is_string($secret) ? new Secret($secret) : null, $given);
    }

    /**
     * Whether it is a client secret for an OIDC client using `private_key_jwt`.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolSettings  $settings
     * @param  string  $name
     * @return bool
     */
    private static function isUnsupported(ProtocolSettings $settings, string $name): bool
    {
        return $settings instanceof OidcSettings
            && $name                                                                     === OidcSetting::CLIENT_SECRET->value
            && ($settings->toArray()[OidcSetting::CLIENT_AUTHENTICATION->value] ?? null) === 'private_key_jwt';
    }

    /**
     * The secret a stored ciphertext decrypted to.
     *
     * @param  string  $plaintext
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \UnexpectedValueException
     */
    private static function secret(string $plaintext): Secret
    {
        if ($plaintext === '') {
            throw new \UnexpectedValueException('A stored secret decrypted to nothing.');
        }

        return new Secret($plaintext);
    }

    /**
     * Each ciphertext stored, by name.
     *
     * @param  ?string  $stored
     * @return array<string, string>
     *
     * @throws \UnexpectedValueException
     */
    private static function decode(?string $stored): array
    {
        if ($stored === null) {
            return [];
        }

        try {
            $decoded = json_decode($stored, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new \UnexpectedValueException(self::MALFORMED);
        }

        if (!is_array($decoded)) {
            throw new \UnexpectedValueException(self::MALFORMED);
        }

        $secrets = [];

        foreach ($decoded as $name => $ciphertext) {

            if (!is_string($name) || !is_string($ciphertext) || $ciphertext === '') {
                throw new \UnexpectedValueException(self::MALFORMED);
            }

            $secrets[$name] = $ciphertext;
        }

        return $secrets;
    }

    /**
     * The connection's row, read again on the write connection unless it is one
     * already; `null` when it is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private static function row(SsoConnection $connection): ?Connection
    {
        if ($connection instanceof Connection) {
            return $connection;
        }

        $id    = $connection->getConnectionId();
        $found = Connection::query()->useWritePdo()->whereKey($id)->first();

        return $found?->id === $id ? $found : null;
    }
}
