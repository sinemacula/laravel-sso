<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Protocols;

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

/**
 * A driver a test registers under a name of its own to start authorisation
 * requests: complete once its issuer is set, it starts by redirecting to
 * `https://idp.example.com/authorize`, or by posting `SAMLRequest` and
 * `RelayState` there when `post` is set, answering the SAML request id, the
 * expected issuer and the `iss` requirement set, or refuses with the reason
 * set. It records every start request it is given, and runs `onStart` once, if
 * it is set, before it answers.
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
final class StartingDriver implements ProtocolDriver
{
    /** @var string The name a test registers the driver under. */
    public const string NAME = 'starting';

    /** @var string Where the driver sends the browser. */
    public const string URL = 'https://idp.example.com/authorize';

    /** @var bool Whether the driver posts a form rather than redirects. */
    public bool $post = false;

    /** @var ?string The SAML request id the driver answers. */
    public ?string $samlRequestId = null;

    /** @var ?string The issuer the driver answers the response must come from. */
    public ?string $expectedIssuer = 'https://idp.example.com';

    /** @var bool Whether the driver answers that the issuer must return `iss`. */
    public bool $issuerRequired = false;

    /** @var ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason The reason the driver refuses with, if any. */
    public ?FailureReason $refusal = null;

    /** @var ?\Closure(): void What runs as the driver next starts, once, before it answers. */
    public ?\Closure $onStart = null;

    /** @var list<\SineMacula\Laravel\Sso\Protocols\StartRequest> Every start request given, in order. */
    private array $starts = [];

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
     * Record the request, run `onStart` once, and redirect, post or refuse as
     * set.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     */
    #[\Override]
    public function start(SsoConnection $connection, StartRequest $request): Start
    {
        unset($connection);

        $this->starts[] = $request;

        $onStart       = $this->onStart;
        $this->onStart = null;

        if ($onStart !== null) {
            $onStart();
        }

        if ($this->refusal !== null) {
            return Start::refused($this->refusal);
        }

        $navigation = $this->post
            ? Navigation::post(self::URL, ['SAMLRequest' => 'PHNhbWxwOkF1dGhuUmVxdWVzdC8+', 'RelayState' => $request->state->reveal()])
            : Navigation::redirect(self::URL . '?client_id=client-123');

        return Start::navigate($navigation, $this->samlRequestId, $this->expectedIssuer, $this->issuerRequired);
    }

    /**
     * Correlate nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     */
    #[\Override]
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
    {
        unset($connection, $request);

        return Correlation::uncorrelated();
    }

    /**
     * Refuse every response.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    #[\Override]
    public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed): Completion
    {
        unset($connection, $request, $consumed);

        return Completion::refused(FailureReason::PROVIDER_ERROR);
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
     * Every start request given, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Protocols\StartRequest>
     */
    public function starts(): array
    {
        return $this->starts;
    }

    /**
     * The last start request given.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\StartRequest
     *
     * @throws \LogicException
     */
    public function lastStart(): StartRequest
    {
        return $this->starts[array_key_last($this->starts) ?? throw new \LogicException('The driver was given no start request.')];
    }
}
