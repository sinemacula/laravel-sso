<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use SineMacula\Laravel\Sso\Responses\CompletionResponse;

/**
 * The redirect a completion sends the browser back to the application with,
 * read as the client reads it (SSO-5.6, SSO-5.7, SSO-12.4): the handoff code of
 * a completed flow, the failure code of a failed one, and the request's public
 * reference either way, from the fragment or the query of the `Location`, the
 * fragment winning when both name one.
 *
 * Give it the `CompletionResponse` the package's response helper answered, or a
 * `Location` read from an HTTP response. A completion that answered no redirect
 * (rejected, or rate limited) is a `LogicException`, and so is asking a failed
 * redirect for its code: the message names the failure, so a test that expected
 * a code says why it has none.
 *
 * Compare the reference with the one your client started the flow with before
 * redeeming the code, as a client must (SSO-5.12). The code never shows in a
 * dump.
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

        // The handoff code the redirect carries, if any
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
     * What a dump shows: never the code.
     *
     * @return array{code: ?string, reference: ?string, error: ?string}
     */
    public function __debugInfo(): array
    {
        return ['code' => $this->hasCode() ? '[redacted]' : null, 'reference' => $this->reference, 'error' => $this->error];
    }

    /**
     * The redirect the response, or the `Location`, sends the browser to.
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
     * The handoff code the redirect carries.
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
     * The parameters of a query or fragment, none when there is none.
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
     * The parameter of the name, when it is a string.
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
