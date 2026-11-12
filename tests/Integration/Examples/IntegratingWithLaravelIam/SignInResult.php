<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

/**
 * A stand-in for `laravel-authentication`'s sign-in result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInResult
{
    /**
     * Constructor.
     *
     * @param  ?string  $sessionId
     * @param  ?string  $reason
     */
    private function __construct(

        /** The session established, when one was. */
        public ?string $sessionId,

        /** Why authentication refused, when it did. */
        public ?string $reason,
    ) {}

    /**
     * A session established.
     *
     * @param  string  $sessionId
     * @return self
     */
    public static function signedIn(string $sessionId): self
    {
        return new self($sessionId, null);
    }

    /**
     * A refusal, for the reason.
     *
     * @param  string  $reason
     * @return self
     */
    public static function failed(string $reason): self
    {
        return new self(null, $reason);
    }

    /**
     * Whether authentication refused the sign-in.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->reason !== null;
    }
}
