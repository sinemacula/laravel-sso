<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use Illuminate\Database\Eloquent\Model;

/**
 * A stand-in for `laravel-audit-log`'s real `Records\PendingRecord`, which this
 * package does not install, with the exact signatures of the builder methods
 * the guide's mapper calls (`docs/guides/events.md`): `event()`, `failed()`,
 * `withProperties()`, `by()`, `forTenant()` and `correlatedWith()`, each
 * validating its value as the sibling's does. It keeps what it was given for a
 * test to read through `toArray()`, which is the stand-in's own; the sibling
 * builds and records its record instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PendingRecord
{
    /** @var string An event code: dot-separated lower-case segments, at least two. */
    private const string CODE_PATTERN = '/\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\z/';

    /** @var string A correlation id: `<namespace>:<value>`. */
    private const string CORRELATION_PATTERN = '/\A[a-z][a-z0-9_-]{0,31}:\S.*\z/u';

    /** @var int The longest correlation id, in characters. */
    private const int ID_MAX_CHARACTERS = 191;

    /** @var array<string, mixed> What the record was given, its properties in their place but kept in `$properties`. */
    private array $given = [
        'code'           => null,
        'outcome'        => 'success',
        'reason'         => null,
        'properties'     => [],
        'actor'          => null,
        'tenant'         => null,
        'correlation_id' => null,
    ];

    /** @var array<array-key, mixed> The properties the record was given. */
    private array $properties = [];

    /**
     * Name what happened with an event code.
     *
     * @param  \BackedEnum|string  $code
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function event(\BackedEnum|string $code): self
    {
        $value = $code instanceof \BackedEnum ? (string) $code->value : $code;

        if (preg_match(self::CODE_PATTERN, $value) !== 1 || str_starts_with($value, 'audit_log.')) {
            throw new \InvalidArgumentException("[{$value}] is not an event code.");
        }

        $this->given['code'] = $value;

        return $this;
    }

    /**
     * Say that the activity was attempted and did not complete, with an
     * optional machine-readable reason.
     *
     * @param  \BackedEnum|string|null  $reason
     * @return self
     */
    public function failed(\BackedEnum|string|null $reason = null): self
    {
        $this->given['outcome'] = 'failure';
        $this->given['reason']  = $reason instanceof \BackedEnum ? (string) $reason->value : $reason;

        return $this;
    }

    /**
     * Name who did it: a model or a reference; `null` says that explicitly no
     * one did.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null  $actor
     * @return self
     */
    public function by(Model|Reference|null $actor): self
    {
        $this->given['actor'] = self::pair($actor);

        return $this;
    }

    /**
     * Name the tenant the activity happened in; `null` says that there is
     * explicitly none.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null  $tenant
     * @return self
     */
    public function forTenant(Model|Reference|null $tenant): self
    {
        $this->given['tenant'] = self::pair($tenant);

        return $this;
    }

    /**
     * Tie the record to other activity with a namespaced id, written
     * `<namespace>:<value>`.
     *
     * @param  string  $correlationId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function correlatedWith(string $correlationId): self
    {
        if (mb_strlen($correlationId, 'UTF-8') > self::ID_MAX_CHARACTERS || preg_match(self::CORRELATION_PATTERN, $correlationId) !== 1) {
            throw new \InvalidArgumentException('A correlation id must be namespaced, as `<namespace>:<value>`, and from 1 to 191 characters with no control characters.');
        }

        $this->given['correlation_id'] = $correlationId;

        return $this;
    }

    /**
     * Describe the activity with properties, merged into those given before.
     *
     * @param  array<array-key, mixed>  $properties
     * @return self
     */
    public function withProperties(#[\SensitiveParameter] array $properties): self
    {
        $this->properties = array_replace($this->properties, $properties);

        return $this;
    }

    /**
     * What the record was given, for a test to read: the stand-in's own.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [...$this->given, 'properties' => $this->properties];
    }

    /**
     * The type and id a model or a reference names, or `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null  $named
     * @return ?array{0: string, 1: string}
     */
    private static function pair(Model|Reference|null $named): ?array
    {
        return match (true) {
            $named instanceof Reference => [$named->type, $named->id],
            $named instanceof Model     => [$named->getMorphClass(), is_scalar($named->getKey()) ? (string) $named->getKey() : ''],
            default                     => null,
        };
    }
}
