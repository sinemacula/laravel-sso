<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use Carbon\CarbonImmutable;

/**
 * The identity provider's authentication context as asserted; the evidence
 * contract, not this, decides whether it satisfies a further factor.
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

        /** The context class (`acr`, `AuthnContextClassRef`). */
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
     * The stored form, holding every value.
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
     * Which parts were stated and how many methods, never a value.
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
     * Restore `toArray()` output from package storage, never client input.
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
     * Refuse too many methods, or one of the wrong length.
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
