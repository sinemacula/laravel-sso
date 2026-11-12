<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use SineMacula\Laravel\Sso\Responses\CompletionResponse;

/**
 * A completion's redirect read as a client reads it: the handoff code or
 * failure, and the reference to compare before redeeming the code.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HandoffRedirect
{
    /** @var \SensitiveParameterValue The handoff code, or `null` when the redirect carries none. */
    private \SensitiveParameterValue $code;

    /**
     * Constructor.
     *
     * @param  ?string  $code
     * @param  ?string  $reference
     * @param  ?string  $error
     */
    private function __construct(

        // Not promoted: held wrapped
        #[\SensitiveParameter]
        ?string $code,

        /** The request's public reference the redirect names, if any. */
        public ?string $reference,

        /** The failure code the redirect names, if any. */
        public ?string $error,
    ) {
        $this->code = new \SensitiveParameterValue($code);
    }

    /**
     * Show everything but the code.
     *
     * @return array{code: ?string, reference: ?string, error: ?string}
     */
    public function __debugInfo(): array
    {
        return ['code' => $this->hasCode() ? '[redacted]' : null, 'reference' => $this->reference, 'error' => $this->error];
    }

    /**
     * Read the redirect from a response or `Location`; the fragment wins over
     * the query.
     *
     * @param  \SineMacula\Laravel\Sso\Responses\CompletionResponse|string|null  $redirect
     * @return self
     *
     * @throws \LogicException
     */
    public static function from(#[\SensitiveParameter] CompletionResponse|string|null $redirect): self
    {
        $location = $redirect instanceof CompletionResponse ? $redirect->location() : $redirect;

        if ($location === null) {
            throw new \LogicException('The completion answered no redirect: it was rejected or rate limited.');
        }

        $parameters = [...self::parameters(parse_url($location, PHP_URL_QUERY)), ...self::parameters(parse_url($location, PHP_URL_FRAGMENT))];

        return new self(self::named($parameters, 'code'), self::named($parameters, 'reference'), self::named($parameters, 'error'));
    }

    /**
     * Whether the redirect carries a handoff code.
     *
     * @return bool
     */
    public function hasCode(): bool
    {
        return $this->code->getValue() !== null;
    }

    /**
     * The handoff code; a failed redirect throws naming the failure.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function code(): string
    {
        $code = $this->code->getValue();

        if (is_string($code)) {
            return $code;
        }

        $why = $this->error === null ? '' : sprintf(': the flow failed with [%s]', $this->error);

        throw new \LogicException(sprintf('The redirect carries no handoff code%s.', $why));
    }

    /**
     * The parameters of a query or fragment.
     *
     * @param  mixed  $part
     * @return array<array-key, mixed>
     */
    private static function parameters(mixed $part): array
    {
        if (!is_string($part)) {
            return [];
        }

        parse_str($part, $parameters);

        return $parameters;
    }

    /**
     * The named parameter, when it is a string.
     *
     * @param  array<array-key, mixed>  $parameters
     * @param  string  $name
     * @return ?string
     */
    private static function named(array $parameters, string $name): ?string
    {
        $value = $parameters[$name] ?? null;

        return is_string($value) ? $value : null;
    }
}
