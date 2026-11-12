<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * The document an administrator registers at the identity provider for a
 * connection, or why there is none. It never holds a secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ServiceProviderDescription
{
    /**
     * Constructor.
     *
     * @param  ?string  $contentType
     * @param  ?string  $body
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The document's media type, for a described connection. */
        public ?string $contentType,

        /** The document, for a described connection. */
        public ?string $body,

        /** Why the connection cannot be described, for an unavailable one. */
        public ?FailureReason $reason,
    ) {}

    /**
     * The connection is described by the document given.
     *
     * @param  string  $contentType
     * @param  string  $body
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function document(string $contentType, string $body): self
    {
        if ($contentType === '' || $body === '') {
            throw new \InvalidArgumentException('A description has a content type and a body.');
        }

        return new self($contentType, $body, null);
    }

    /**
     * The connection cannot be described, for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function unavailable(FailureReason $reason): self
    {
        return new self(null, null, $reason);
    }

    /**
     * Whether the connection is described.
     *
     * @return bool
     */
    public function isAvailable(): bool
    {
        return $this->reason === null;
    }
}
