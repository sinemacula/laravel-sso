<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * A connection's secrets (SSO-2.5), as its `secrets` column holds them: a JSON
 * object of each secret's name and its ciphertext from
 * `Contracts\SecretEncrypter`, each secret encrypted on its own, or `null` when
 * none is set.
 *
 * Which secrets are set is read from the names alone, so a read masks them
 * without decrypting one. Only `reveal()` decrypts, for the flow that must send
 * the secret, and hands it on as a `Secrets\Secret`, which never shows it in a
 * dump, a log or a serialisation. Nothing here logs a secret, echoes one or
 * puts one in an exception, and every parameter that carries a secret given in
 * plaintext is `#[\SensitiveParameter]`, so a trace shows it redacted: a column
 * that is not such an object is an `UnexpectedValueException` that names
 * neither its content nor a secret, and the encrypter's own failure propagates
 * as a server error (SSO-11.4).
 *
 * It also judges the secrets a change gives and names those the change alters,
 * so every management helper treats a secret alike.
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
     * The names of the secrets the connection has set, as stored, without
     * decrypting one.
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
     * The secret under the name, decrypted for the flow that must send it, or
     * `null` when it is not set.
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
     * The column after the changes: a secret given sets or replaces the one
     * under its name, `null` removes it, and a name not given keeps what is
     * stored. `null` when no secret remains.
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
     * The problems with the secrets given, in the order the protocol declares
     * them: each a string of 1 to 1024 bytes with no control character, and,
     * over OIDC, no client secret for a client that authenticates with
     * `private_key_jwt`. A secret given as `null` is cleared, never refused,
     * and no violation holds the value.
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
     * The names of the secrets a change alters, in the order the protocol
     * declares them: each given as a string, and each given as `null` that is
     * stored.
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
     * The secrets given, validated, as the changes `apply()` takes: a string
     * sets the secret, and `null` clears it.
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
     * Whether the secret cannot be used with the settings: a client secret for
     * an OIDC client that authenticates with `private_key_jwt`.
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
}
