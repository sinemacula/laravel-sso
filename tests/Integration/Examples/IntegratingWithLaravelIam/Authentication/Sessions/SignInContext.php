<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Http\Request;

/**
 * A stand-in for `laravel-authentication`'s `Sessions\SignInContext`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInContext
{
    /**
     * Constructor.
     *
     * @param  ?string  $ip
     */
    public function __construct(

        /** The IP address the sign-in came from. */
        public ?string $ip,
    ) {}

    /**
     * Read the context of a sign-in from its request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        return new self($request->ip());
    }
}
