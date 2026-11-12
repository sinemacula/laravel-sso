<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\StrictJson;

/**
 * An OpenID provider's discovery document for one issuer, read strictly.
 *
 * Its values are untrusted, so a dump shows names alone and it refuses to be
 * serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-type DiscoverySettings array{
 *     issuer: string,
 *     authorization_endpoint: string,
 *     token_endpoint: string,
 *     jwks_uri: string,
 *     userinfo_endpoint?: string,
 *     returns_iss: bool,
 *     id_token_algorithms: list<string>
 * }
 * @phpstan-type DiscoveryValues array{
 *     settings: array{
 *         issuer: string,
 *         authorization_endpoint: string,
 *         token_endpoint: string,
 *         jwks_uri: string,
 *         userinfo_endpoint?: string,
 *         returns_iss: bool,
 *         id_token_algorithms: list<string>
 *     },
 *     auth_methods: list<string>
 * }
 */
final readonly class DiscoveryDocument implements \JsonSerializable
{
    /** @var string The response types the provider supports. */
    private const string RESPONSE_TYPES = 'response_types_supported';

    /** @var string The ID token algorithms the provider supports. */
    private const string SIGNING_ALGORITHMS = 'id_token_signing_alg_values_supported';

    /** @var string The PKCE methods the provider supports. */
    private const string CHALLENGE_METHODS = 'code_challenge_methods_supported';

    /** @var string The client authentication methods the provider supports. */
    private const string AUTH_METHODS = 'token_endpoint_auth_methods_supported';

    /** @var string The RFC 9207 flag. */
    private const string RETURNS_ISS = 'authorization_response_iss_parameter_supported';

    /** @var list<string> The lists a document may leave out. */
    private const array OPTIONAL_LISTS = ['subject_types_supported', self::CHALLENGE_METHODS, self::AUTH_METHODS];

    /** @var ?\SensitiveParameterValue The values read, for a read document. */
    private ?\SensitiveParameterValue $values;

    /**
     * Constructor.
     *
     * @param  ?DiscoveryValues  $values
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        // The values read; held wrapped
        #[\SensitiveParameter]
        ?array $values,

        /** Why it was refused, for a refused document. */
        public ?FailureReason $reason,
    ) {
        $this->values = $values === null ? null : new \SensitiveParameterValue($values);
    }

    /**
     * What a dump shows: whether it was read, why not, and the names of its
     * settings, never a value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'read'     => $this->isRead(),
            'reason'   => $this->reason?->value,
            'settings' => $this->isRead() ? array_keys($this->all()['settings']) : [],
        ];
    }

    /**
     * Refuse to be serialised: a document lives only for its import or refresh.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A discovery document cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A discovery document cannot be unserialised.');
    }

    /**
     * The document the body holds for the issuer, or its refusal.
     *
     * @param  string  $json
     * @param  string  $issuer
     * @param  int  $maxBytes
     * @return self
     */
    public static function read(#[\SensitiveParameter] string $json, string $issuer, int $maxBytes): self
    {
        $written = strlen($json) > $maxBytes ? null : StrictJson::decodeAsWritten($json);

        if ($written === null) {
            return new self(null, FailureReason::DISCOVERY_INVALID);
        }

        $document = (array) $written;
        $reason   = self::refusal($document, $issuer);

        return $reason === null ? new self(self::valuesOf($document), null) : new self(null, $reason);
    }

    /**
     * Whether the document was read.
     *
     * @return bool
     *
     * @phpstan-assert-if-false !null $this->reason
     */
    public function isRead(): bool
    {
        return $this->values !== null;
    }

    /**
     * The settings the document gives, by the names a connection holds them
     * under, in the order `OidcSetting` names them.
     *
     * @return DiscoverySettings
     *
     * @throws \LogicException
     */
    public function settings(): array
    {
        return $this->all()['settings'];
    }

    /**
     * The URL the document names for the provider's JWKS.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function jwksUri(): string
    {
        return $this->settings()[OidcSetting::JWKS_URI->value];
    }

    /**
     * The algorithms the provider supports that are on the package's list, in
     * the package's order; never empty.
     *
     * @return list<string>
     *
     * @throws \LogicException
     */
    public function algorithms(): array
    {
        return $this->settings()[OidcSetting::ID_TOKEN_ALGORITHMS->value];
    }

    /**
     * The client authentication methods the document lists, as it lists them.
     *
     * @return list<string>
     *
     * @throws \LogicException
     */
    public function authMethods(): array
    {
        return $this->all()['auth_methods'];
    }

    /**
     * What `json_encode()` writes: what a dump shows.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * Everything read.
     *
     * @return DiscoveryValues
     *
     * @throws \LogicException
     */
    private function all(): array
    {
        if ($this->values === null) {
            throw new \LogicException('A refused discovery document holds no values.');
        }

        /** @var DiscoveryValues */
        return $this->values->getValue();
    }

    /**
     * Why the members are refused for the issuer, or `null` when they are read.
     *
     * @param  array<array-key, mixed>  $document
     * @param  string  $issuer
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function refusal(array $document, string $issuer): ?FailureReason
    {
        return match (true) {
            ($document[OidcSetting::ISSUER->value] ?? null) !== $issuer                           => FailureReason::ISSUER_MISMATCH,
            !self::hasEndpoints($document), !self::hasLists($document), !self::hasFlag($document) => FailureReason::DISCOVERY_INVALID,
            default                                                                               => null,
        };
    }

    /**
     * Whether the required endpoints, and the UserInfo endpoint when present,
     * are each a valid setting.
     *
     * @param  array<array-key, mixed>  $document
     * @return bool
     */
    private static function hasEndpoints(array $document): bool
    {
        foreach ([OidcSetting::AUTHORIZATION_ENDPOINT, OidcSetting::TOKEN_ENDPOINT, OidcSetting::JWKS_URI] as $endpoint) {
            if (SettingRules::url($document[$endpoint->value] ?? null) !== null) {
                return false;
            }
        }

        $userInfo = OidcSetting::USERINFO_ENDPOINT->value;

        return !array_key_exists($userInfo, $document) || SettingRules::url($document[$userInfo]) === null;
    }

    /**
     * Whether every list is a list of strings, the required ones given, holding
     * `code`, `S256` and an algorithm of the package's.
     *
     * @param  array<array-key, mixed>  $document
     * @return bool
     */
    private static function hasLists(array $document): bool
    {
        $optional = array_intersect_key($document, array_flip(self::OPTIONAL_LISTS));
        $required = [$document[self::RESPONSE_TYPES] ?? null, $document[self::SIGNING_ALGORITHMS] ?? null];

        foreach ([...$optional, ...$required] as $list) {
            if (!self::isStringList($list)) {
                return false;
            }
        }

        $code = in_array('code', (array) $document[self::RESPONSE_TYPES], true);
        $s256 = !array_key_exists(self::CHALLENGE_METHODS, $document) || in_array('S256', (array) $document[self::CHALLENGE_METHODS], true);

        return $code && $s256 && self::algorithmsOf($document) !== [];
    }

    /**
     * Whether the RFC 9207 flag, when present, is a boolean.
     *
     * @param  array<array-key, mixed>  $document
     * @return bool
     */
    private static function hasFlag(array $document): bool
    {
        return !array_key_exists(self::RETURNS_ISS, $document) || is_bool($document[self::RETURNS_ISS]);
    }

    /**
     * Whether the value is a list of strings.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isStringList(mixed $value): bool
    {
        return is_array($value) && array_is_list($value) && array_filter($value, is_string(...)) === $value;
    }

    /**
     * The algorithms the document supports that are on the package's list, in
     * the package's order.
     *
     * @param  array<array-key, mixed>  $document
     * @return list<string>
     */
    private static function algorithmsOf(array $document): array
    {
        /** @var list<string> $supported */
        $supported = $document[self::SIGNING_ALGORITHMS];

        return array_values(array_filter(array_keys(AlgorithmAllowList::ALGORITHMS), static fn (string $algorithm): bool => in_array($algorithm, $supported, true)));
    }

    /**
     * The typed values of a document every rule accepted.
     *
     * @param  array<array-key, mixed>  $document
     * @return DiscoveryValues
     */
    private static function valuesOf(array $document): array
    {
        $userInfo = OidcSetting::USERINFO_ENDPOINT->value;

        /** @var DiscoveryValues */
        return [
            'settings' => [
                OidcSetting::ISSUER->value                 => $document[OidcSetting::ISSUER->value],
                OidcSetting::AUTHORIZATION_ENDPOINT->value => $document[OidcSetting::AUTHORIZATION_ENDPOINT->value],
                OidcSetting::TOKEN_ENDPOINT->value         => $document[OidcSetting::TOKEN_ENDPOINT->value],
                OidcSetting::JWKS_URI->value               => $document[OidcSetting::JWKS_URI->value],
                ...(array_key_exists($userInfo, $document) ? [$userInfo => $document[$userInfo]] : []),
                OidcSetting::RETURNS_ISS->value         => ($document[self::RETURNS_ISS] ?? false) === true,
                OidcSetting::ID_TOKEN_ALGORITHMS->value => self::algorithmsOf($document),
            ],
            'auth_methods' => $document[self::AUTH_METHODS] ?? [],
        ];
    }
}
