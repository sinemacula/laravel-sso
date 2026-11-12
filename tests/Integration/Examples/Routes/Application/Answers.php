<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Application;

use Illuminate\Http\JsonResponse;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Domains\DomainResult;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\LinkResult;

/**
 * The HTTP responses the example application's routes answer results with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Answers
{
    /** @var array<string, string> The headers every answer carries. */
    public const array NO_STORE = ['Cache-Control' => 'no-store'];

    /** @var list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason> Answered as `404`. */
    private const array NOT_FOUND = [FailureReason::CONNECTION_NOT_FOUND, FailureReason::DOMAIN_NOT_FOUND, FailureReason::LINK_NOT_FOUND];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The response for the result, with the body given replacing it on success.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult|\SineMacula\Laravel\Sso\Domains\DomainResult|\SineMacula\Laravel\Sso\Links\LinkResult  $result
     * @param  int  $success
     * @param  ?array<string, mixed>  $body
     * @return \Illuminate\Http\JsonResponse
     */
    public static function of(ConnectionResult|DomainResult|LinkResult $result, int $success = 200, ?array $body = null): JsonResponse
    {
        $status = self::status($result, $success);
        $retry  = $result instanceof DomainResult && $result->retryAfter !== null ? ['Retry-After' => (string) $result->retryAfter] : [];

        return response()->json($status === $success && $body !== null ? $body : $result, $status, [...self::NO_STORE, ...$retry]);
    }

    /**
     * A refusal of a flow, by its reason's code.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \Illuminate\Http\JsonResponse
     */
    public static function refused(FailureReason $reason): JsonResponse
    {
        return response()->json(['error' => $reason->value], 400, self::NO_STORE);
    }

    /**
     * A full limit, with when to try again.
     *
     * @param  ?int  $retryAfter
     * @return \Illuminate\Http\JsonResponse
     */
    public static function rateLimited(?int $retryAfter): JsonResponse
    {
        return response()->json(['error' => FailureReason::RATE_LIMITED->value], 429, [...self::NO_STORE, 'Retry-After' => (string) $retryAfter]);
    }

    /**
     * The status the result answers with.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult|\SineMacula\Laravel\Sso\Domains\DomainResult|\SineMacula\Laravel\Sso\Links\LinkResult  $result
     * @param  int  $success
     * @return int
     */
    private static function status(ConnectionResult|DomainResult|LinkResult $result, int $success): int
    {
        $succeeded = $result instanceof LinkResult ? $result->isRemoved() : $result->isSucceeded();
        $invalid   = !$result instanceof LinkResult && $result->isInvalid();

        return match (true) {
            $succeeded                                            => $success,
            $invalid                                              => 422,
            $result->reason === FailureReason::FRESHNESS_REQUIRED => 403,
            in_array($result->reason, self::NOT_FOUND, true)      => 404,
            $result->reason === FailureReason::RATE_LIMITED       => 429,
            default                                               => 409,
        };
    }
}
