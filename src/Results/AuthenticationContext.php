<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use Carbon\CarbonImmutable;

/**
 * The identity provider's authentication context, as its validated assertion
 * stated it (SSO-6.10, SSO-8.1, SSO-8.7): when the person authenticated
 * (`AuthnInstant`, `auth_time`), how (`amr`), at what class (`acr`, or the SAML
 * `AuthnContextClassRef`), the provider session's id (`SessionIndex`, the ID
 * token's `sid`) and the provider session's deadline (`SessionNotOnOrAfter`).
 *
 * Every part is carried as asserted, and never treated as satisfying the
 * application's further factor: the evidence contract decides that. Each string
 * is 1 to 1024 bytes, each method 1 to 255, and at most 32 methods are kept; a
 * part the assertion did not state is `null` (or no methods).
 *
 * `toArray()` is the stored form, holding every value. `json_encode()`, and a
 * logger's normaliser that falls back to it, write only which parts were stated
 * and how many methods, never a value the provider asserted.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthenticationContext implements \JsonSerializable
{
    /** @var int The most methods kept. */
    public const int MAX_METHODS = 32;

    /** @var int The longest method, in bytes. */
    public const int MAX_METHOD_LENGTH = 255;

    /** @var int The longest class or session id, in bytes. */
    public const int MAX_VALUE_LENGTH = 1024;

    /**
     * Constructor.
     *
     * @param  ?\Carbon\CarbonImmutable  $authenticatedAt
     * @param  list<string>  $methods
     * @param  ?string  $contextClass
     * @param  ?string  $providerSessionId
     * @param  ?\Carbon\CarbonImmutable  $providerSessionDeadline
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** When the person authenticated at the identity provider. */
        public ?CarbonImmutable $authenticatedAt = null,

        /** The authentication methods asserted (`amr`), in order. */
        public array $methods = [],

        /** The authentication context class asserted (`acr`, `AuthnContextClassRef`). */
        public ?string $contextClass = null,

        /** The provider session's id (`SessionIndex`, `sid`). */
        public ?string $providerSessionId = null,

        /** When the provider asks the session to end (`SessionNotOnOrAfter`). */
        public ?CarbonImmutable $providerSessionDeadline = null,
    ) {
        self::assertMethods($methods);
        StoredValues::assertOptionalText('authentication context class', $contextClass, self::MAX_VALUE_LENGTH);
        StoredValues::assertOptionalText('provider session id', $providerSessionId, self::MAX_VALUE_LENGTH);
    }

    /**
     * The context as stored, with snake_case keys.
     *
     * @return array{authenticated_at: ?string, methods: list<string>, context_class: ?string, provider_session_id: ?string, provider_session_deadline: ?string}
     */
    public function toArray(): array
    {
        return [
            'authenticated_at'          => StoredValues::instant($this->authenticatedAt),
            'methods'                   => $this->methods,
            'context_class'             => $this->contextClass,
            'provider_session_id'       => $this->providerSessionId,
            'provider_session_deadline' => StoredValues::instant($this->providerSessionDeadline),
        ];
    }

    /**
     * What `json_encode()` writes: each part as `[redacted]` when stated and
     * `null` when not, and the number of methods, never a value.
     *
     * @return array{authenticated_at: ?string, methods: int, context_class: ?string, provider_session_id: ?string, provider_session_deadline: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'authenticated_at'          => StoredValues::redacted($this->authenticatedAt),
            'methods'                   => count($this->methods),
            'context_class'             => StoredValues::redacted($this->contextClass),
            'provider_session_id'       => StoredValues::redacted($this->providerSessionId),
            'provider_session_deadline' => StoredValues::redacted($this->providerSessionDeadline),
        ];
    }

    /**
     * The context `toArray()` stored, read back from the package's own
     * storage; never from client input.
     *
     * @param  array<array-key, mixed>  $stored
     * @return self
     *
     * @throws \UnexpectedValueException
     *
     * @internal
     */
    public static function restore(array $stored): self
    {
        $methods = StoredValues::array($stored, 'methods');

        return StoredValues::restoring(static fn (): self => new self(
            StoredValues::restoredInstant($stored['authenticated_at'] ?? null),
            $methods, // @phpstan-ignore argument.type
            StoredValues::optionalString($stored, 'context_class'),
            StoredValues::optionalString($stored, 'provider_session_id'),
            StoredValues::restoredInstant($stored['provider_session_deadline'] ?? null),
        ));
    }

    /**
     * Refuse more methods than are kept, or a method that is not 1 to 255
     * bytes.
     *
     * @param  array<array-key, mixed>  $methods
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertMethods(array $methods): void
    {
        if (!array_is_list($methods) || count($methods) > self::MAX_METHODS) {
            throw new \InvalidArgumentException(sprintf('A verified result keeps a list of at most %d authentication methods.', self::MAX_METHODS));
        }

        foreach ($methods as $method) {

            if (!is_string($method)) {
                throw new \InvalidArgumentException('Each authentication method is a string.');
            }

            StoredValues::assertText('authentication method', $method, self::MAX_METHOD_LENGTH);
        }
    }
}
