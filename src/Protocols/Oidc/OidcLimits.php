<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * The `sso.oidc` caps, windows and timeouts, read on each call. A malformed
 * value throws, and a cap can be lowered but never raised past its ceiling.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OidcLimits
{
    /** @var int The longest ID token when none is configured, and the ceiling, in bytes. */
    public const int MAX_ID_TOKEN_BYTES = 16384;

    /** @var int The largest JWKS when none is configured, and the ceiling, in bytes. */
    public const int MAX_JWKS_BYTES = 65536;

    /** @var int The most keys in a JWKS when none is configured, and the ceiling. */
    public const int MAX_JWKS_KEYS = 50;

    /** @var int The default discovery, token and UserInfo response cap, in bytes. */
    public const int DEFAULT_RESPONSE_BYTES = 65536;

    /** @var int The ceiling of a discovery document, token or UserInfo response cap, in bytes. */
    public const int MAX_RESPONSE_BYTES = 1048576;

    /** @var int The longest callback parameter when none is configured, and the ceiling, in bytes. */
    public const int MAX_CALLBACK_PARAMETER_BYTES = 2048;

    /** @var int The longest raw callback query when none is configured, in bytes. */
    public const int DEFAULT_CALLBACK_QUERY_BYTES = 8192;

    /** @var int The most callback parameters when none is configured. */
    public const int DEFAULT_CALLBACK_PARAMETERS = 16;

    /** @var int The JWKS refetch cooldown when none is configured, in seconds. */
    public const int DEFAULT_JWKS_REFETCH_COOLDOWN_SECONDS = 300;

    /** @var int The oldest ID token `iat` when none is configured, in seconds. */
    public const int DEFAULT_ID_TOKEN_MAX_AGE_SECONDS = 300;

    /** @var int The token and UserInfo timeout when none is configured, in seconds. */
    public const int DEFAULT_TIMEOUT_SECONDS = 10;

    /** @var int The smallest response or JWKS cap, in bytes. */
    private const int MIN_DOCUMENT_BYTES = 4096;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the limits are read from. */
        private Repository $config,
    ) {}

    /**
     * The longest ID token, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxIdTokenBytes(): int
    {
        return $this->read('max_id_token_bytes', self::MAX_ID_TOKEN_BYTES, 2048, self::MAX_ID_TOKEN_BYTES);
    }

    /**
     * The largest JWKS, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxJwksBytes(): int
    {
        return $this->read('max_jwks_bytes', self::MAX_JWKS_BYTES, self::MIN_DOCUMENT_BYTES, self::MAX_JWKS_BYTES);
    }

    /**
     * The most keys a JWKS holds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxJwksKeys(): int
    {
        return $this->read('max_jwks_keys', self::MAX_JWKS_KEYS, 1, self::MAX_JWKS_KEYS);
    }

    /**
     * The largest discovery document, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxDiscoveryBytes(): int
    {
        return $this->read('max_discovery_bytes', self::DEFAULT_RESPONSE_BYTES, self::MIN_DOCUMENT_BYTES, self::MAX_RESPONSE_BYTES);
    }

    /**
     * The largest token response, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxTokenResponseBytes(): int
    {
        return $this->read('max_token_response_bytes', self::DEFAULT_RESPONSE_BYTES, self::MIN_DOCUMENT_BYTES, self::MAX_RESPONSE_BYTES);
    }

    /**
     * The largest UserInfo response, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxUserInfoBytes(): int
    {
        return $this->read('max_userinfo_bytes', self::DEFAULT_RESPONSE_BYTES, self::MIN_DOCUMENT_BYTES, self::MAX_RESPONSE_BYTES);
    }

    /**
     * The longest callback parameter name or value, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxCallbackParameterBytes(): int
    {
        return $this->read('max_callback_parameter_bytes', self::MAX_CALLBACK_PARAMETER_BYTES, 256, self::MAX_CALLBACK_PARAMETER_BYTES);
    }

    /**
     * The longest raw callback query, in bytes.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxCallbackQueryBytes(): int
    {
        return $this->read('max_callback_query_bytes', self::DEFAULT_CALLBACK_QUERY_BYTES, 1024, 16384);
    }

    /**
     * The most parameters a callback query holds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxCallbackParameters(): int
    {
        return $this->read('max_callback_parameters', self::DEFAULT_CALLBACK_PARAMETERS, 4, 32);
    }

    /**
     * The least time between two JWKS refetches on an unknown `kid`, in
     * seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function jwksRefetchCooldownSeconds(): int
    {
        return $this->read('jwks_refetch_cooldown_seconds', self::DEFAULT_JWKS_REFETCH_COOLDOWN_SECONDS, 60, 3600);
    }

    /**
     * How old an ID token's `iat` may be, in seconds, before the clock skew.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function idTokenMaxAgeSeconds(): int
    {
        return $this->read('id_token_max_age_seconds', self::DEFAULT_ID_TOKEN_MAX_AGE_SECONDS, 30, 3600);
    }

    /**
     * The whole time a token request may take, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function tokenTimeoutSeconds(): int
    {
        return $this->read('token_timeout_seconds', self::DEFAULT_TIMEOUT_SECONDS, 1, 60);
    }

    /**
     * The whole time a UserInfo request may take, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function userInfoTimeoutSeconds(): int
    {
        return $this->read('userinfo_timeout_seconds', self::DEFAULT_TIMEOUT_SECONDS, 1, 60);
    }

    /**
     * Read the named `sso.oidc.` limit within its bounds.
     *
     * @param  string  $name
     * @param  int  $default
     * @param  int  $least
     * @param  int  $most
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function read(string $name, int $default, int $least, int $most): int
    {
        return IntegerSetting::read($this->config, 'sso.oidc.' . $name, $default, $least, $most);
    }
}
