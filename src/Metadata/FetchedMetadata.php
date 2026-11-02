<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;

/**
 * What a refresh's fetch found (SSO-2.8): the document a source read and
 * validated whole, with the moment it validated it, or why there is none (a
 * fetch refused or failed, a response not `2xx`, a document refused); and how
 * the fetch itself ended, which a refresh that did not apply logs.
 *
 * The document is the source's own (`Protocols\Saml2\Messages\IdpMetadata`, the
 * OIDC source's discovery document and JWKS), held in a
 * `\SensitiveParameterValue`; a dump shows none of it, and it refuses to be
 * serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FetchedMetadata
{
    /** @var ?\SensitiveParameterValue The document read, for a read one. */
    private ?\SensitiveParameterValue $document;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus  $fetchStatus
     * @param  ?object  $document
     * @param  ?\Carbon\CarbonImmutable  $validatedAt
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** How the fetch ended. */
        public FetchStatus $fetchStatus,

        // The document read; held wrapped
        ?object $document,

        /** The moment the document was validated, for a read one. */
        public ?CarbonImmutable $validatedAt,

        /** Why there is no document, for one refused. */
        public ?FailureReason $reason,
    ) {
        $this->document = $document === null ? null : new \SensitiveParameterValue($document);
    }

    /**
     * What a dump shows: how the fetch ended, when the document was validated
     * and why there is none, never the document.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'fetch_status' => $this->fetchStatus->value,
            'document'     => $this->document === null ? null : '[redacted]',
            'validated_at' => $this->validatedAt?->toIso8601String(),
            'reason'       => $this->reason?->value,
        ];
    }

    /**
     * Refuse to be serialised: what was fetched lives only for its refresh.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('Fetched metadata cannot be serialised.');
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
        throw new \LogicException('Fetched metadata cannot be unserialised.');
    }

    /**
     * The document was fetched and validated whole at the moment given.
     *
     * @param  object  $document
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @return self
     */
    public static function read(object $document, CarbonImmutable $validatedAt): self
    {
        return new self(FetchStatus::FETCHED, $document, $validatedAt, null);
    }

    /**
     * There is no document, for the reason given; the fetch ended as given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus  $fetchStatus
     * @return self
     */
    public static function refused(FailureReason $reason, FetchStatus $fetchStatus): self
    {
        return new self($fetchStatus, null, null, $reason);
    }

    /**
     * Whether a document was read.
     *
     * @return bool
     *
     * @phpstan-assert-if-true !null $this->validatedAt
     *
     * @phpstan-assert-if-false !null $this->reason
     */
    public function isRead(): bool
    {
        return $this->document !== null;
    }

    /**
     * The document read, for the source that read it; `null` for none.
     *
     * @return ?object
     */
    public function document(): ?object
    {
        /** @var ?object */
        return $this->document?->getValue();
    }
}
