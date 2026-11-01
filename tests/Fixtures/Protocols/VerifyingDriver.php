<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Protocols;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;

/**
 * A driver a test registers under a name of its own to complete flows: complete
 * once its issuer is set, it correlates a response by its `state` query
 * parameter, or by its posted `state` and `in_response_to` fields, or answers
 * the correlation set; it verifies every response with the claims set (by
 * default `claims()`), or refuses with the reason set. It records each consumed
 * request it is asked to validate against, and runs `onComplete` once, if it is
 * set, before it answers.
 *
 * A test keeps the instance and registers it with
 * `ProtocolManager::extend(self::NAME, fn () => $driver)`, so it reads what the
 * driver recorded and changes what it answers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VerifyingDriver implements ProtocolDriver
{
    /** @var string The name a test registers the driver under. */
    public const string NAME = 'verifying';

    /** @var string The issuer the default claims come from. */
    public const string ISSUER = 'https://idp.example.com';

    /** @var string The subject the default claims carry, exactly as received. */
    public const string SUBJECT = ' Subject-1 ';

    /** @var string The provider session deadline the default claims carry. */
    public const string DEADLINE = '2026-11-01T18:00:00Z';

    /** @var ?\SineMacula\Laravel\Sso\Protocols\Correlation The correlation answered instead of reading the response, when set. */
    public ?Correlation $correlation = null;

    /** @var ?\SineMacula\Laravel\Sso\Results\VerifiedClaims The claims every response is verified with, when set. */
    public ?VerifiedClaims $claims = null;

    /** @var ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason The reason every response is refused with, when set. */
    public ?FailureReason $refusal = null;

    /** @var ?\Closure(): void What runs as the driver next validates, once, before it answers. */
    public ?\Closure $onComplete = null;

    /** @var int How many responses the driver was asked to correlate. */
    private int $correlations = 0;

    /** @var list<\SineMacula\Laravel\Sso\Protocols\ConsumedRequest> Every consumed request a response was validated against, in order. */
    private array $completions = [];

    /**
     * The example settings the values give.
     *
     * @param  array<array-key, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
     */
    #[\Override]
    public function settings(array $values): ProtocolSettings
    {
        return ExampleSettings::fromArray($values);
    }

    /**
     * Complete once the issuer is set.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     */
    #[\Override]
    public function isComplete(SsoConnection $connection): bool
    {
        return $this->settings($connection->getSettings())->isComplete();
    }

    /**
     * Redirect to the provider.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     */
    #[\Override]
    public function start(SsoConnection $connection, StartRequest $request): Start
    {
        unset($connection, $request);

        return Start::navigate(Navigation::redirect(self::ISSUER . '/authorize'), expectedIssuer: self::ISSUER);
    }

    /**
     * The correlation set, or the response's `state` and `in_response_to`.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     */
    #[\Override]
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
    {
        unset($connection);

        $this->correlations++;

        if ($this->correlation !== null) {
            return $this->correlation;
        }

        parse_str($request->query(), $query);

        $body  = $request->body();
        $state = self::text($query['state'] ?? $body['state'] ?? null);
        $id    = self::text($body['in_response_to'] ?? null);

        return $state === null && $id === null ? Correlation::uncorrelated() : Correlation::solicited($state, $id);
    }

    /**
     * Record the consumed request, run `onComplete` once, and verify or refuse
     * as set.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    #[\Override]
    public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed): Completion
    {
        unset($connection, $request);

        $this->completions[] = $consumed;

        $onComplete       = $this->onComplete;
        $this->onComplete = null;

        if ($onComplete !== null) {
            $onComplete();
        }

        return $this->refusal === null ? Completion::verified($this->claims ?? self::claims()) : Completion::refused($this->refusal);
    }

    /**
     * A JSON document naming the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    #[\Override]
    public function describe(SsoConnection $connection): ServiceProviderDescription
    {
        return ServiceProviderDescription::document('application/json', (string) json_encode(['connection' => $connection->getConnectionId()]));
    }

    /**
     * How many responses the driver was asked to correlate.
     *
     * @return int
     */
    public function correlations(): int
    {
        return $this->correlations;
    }

    /**
     * Every consumed request a response was validated against, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Protocols\ConsumedRequest>
     */
    public function completions(): array
    {
        return $this->completions;
    }

    /**
     * The claims every response is verified with by default: the issuer and
     * subject, raw attributes for an email, a name and groups, and an
     * authentication context with a provider session deadline.
     *
     * @param  array<string, mixed>  $attributes
     * @param  ?\Carbon\CarbonImmutable  $deadline
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    public static function claims(?array $attributes = null, ?CarbonImmutable $deadline = null): VerifiedClaims
    {
        return new VerifiedClaims(
            self::ISSUER,
            self::SUBJECT,
            null,
            $attributes ?? ['mail' => 'person@example.com', 'given' => ['Ada', 'Augusta'], 'memberOf' => ['staff', 'admins'], 'secret' => 'not mapped'],
            new AuthenticationContext(
                CarbonImmutable::parse('2026-11-01T09:29:00Z'),
                ['pwd'],
                null,
                'provider-session-1',
                $deadline ?? CarbonImmutable::parse(self::DEADLINE),
            ),
        );
    }

    /**
     * The value when it is a non-empty string, and `null` otherwise.
     *
     * @param  mixed  $value
     * @return ?string
     */
    private static function text(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
