<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * A `sign_in` result resolved to no identity, so a listener may provision one
 * through `Provisioning\ProvisioningHelper` with the grant.
 *
 * Dispatched synchronously before any handoff: a listener must create a new
 * identity, never resolve an existing one from the result's attributes.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property \SineMacula\Laravel\Sso\Results\VerifiedResult $result
 */
final readonly class ResultUnlinked implements \JsonSerializable, SsoEvent
{
    /** @var \SensitiveParameterValue The exact result the grant is bound to, held wrapped. */
    private \SensitiveParameterValue $held;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     */
    public function __construct(

        /** Who and what the result concerns. */
        public EventContext $context,

        // Not promoted: held wrapped, so no dump, export or array cast shows it
        #[\SensitiveParameter]
        VerifiedResult $result,

        /** What the provisioning helper links with, once, during this dispatch. */
        public ProvisioningGrant $grant,
    ) {
        $this->held = new \SensitiveParameterValue($result);
    }

    /**
     * The result, as `$event->result`; nothing else is read this way.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \LogicException
     */
    public function __get(string $name): VerifiedResult
    {
        if ($name !== 'result') {
            throw new \LogicException(sprintf('The unlinked-result event has no [%s].', $name));
        }

        /** @var \SineMacula\Laravel\Sso\Results\VerifiedResult */
        return $this->held->getValue();
    }

    /**
     * Whether `$event->result` is what is asked about.
     *
     * @param  string  $name
     * @return bool
     */
    public function __isset(string $name): bool
    {
        return $name === 'result';
    }

    /**
     * What a dump shows: the context, never the result.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['context' => $this->context, 'result' => '[redacted]', 'grant' => '[redacted]'];
    }

    /**
     * Refuse to be serialised: a queued listener is too late.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('The unlinked-result event cannot be serialised: a queued listener is too late.');
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
        throw new \LogicException('The unlinked-result event cannot be unserialised.');
    }

    /**
     * What `json_encode()` writes: the context, never the result.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['context' => $this->context->toArray()];
    }

    /**
     * Return who and what the event concerns.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
