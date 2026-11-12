<?php

declare(strict_types = 1);

namespace Tests\Unit\Fetching;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for how an outbound request ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FetchResult::class)]
#[CoversClass(FetchStatus::class)]
final class FetchResultTest extends TestCase
{
    /**
     * A fetched response keeps its status, lower-cased headers and body, and is
     * successful only on `2xx`.
     *
     * @return void
     */
    public function testAFetchedResponseKeepsWhatCameBack(): void
    {
        $result = FetchResult::fetched(200, ['Content-Type' => 'application/json'], '{"keys":[]}');

        self::assertSame(FetchStatus::FETCHED, $result->status);
        self::assertTrue($result->isFetched());
        self::assertTrue($result->isSuccessful());
        self::assertSame(200, $result->statusCode);
        self::assertSame('application/json', $result->header('content-type'));
        self::assertSame('application/json', $result->header('CONTENT-TYPE'));
        self::assertNull($result->header('location'));
        self::assertSame('{"keys":[]}', $result->body());
        self::assertNull($result->reason);

        foreach ([199 => false, 299 => true, 300 => false, 400 => false] as $code => $successful) {
            self::assertSame($successful, FetchResult::fetched($code, [], '')->isSuccessful(), "Status {$code}");
        }
    }

    /**
     * A refusal and a failure carry their reason code and nothing of a
     * response.
     *
     * @return void
     */
    public function testARefusalAndAFailureCarryTheirReasonOnly(): void
    {
        $refused = FetchResult::refused();
        $failed  = FetchResult::failed();

        self::assertSame([FetchStatus::REFUSED, FailureReason::FETCH_REFUSED], [$refused->status, $refused->reason]);
        self::assertSame([FetchStatus::FAILED, FailureReason::FETCH_FAILED], [$failed->status, $failed->reason]);

        foreach ([$refused, $failed] as $result) {
            self::assertFalse($result->isFetched());
            self::assertFalse($result->isSuccessful());
            self::assertNull($result->statusCode);
            self::assertNull($result->body());
            self::assertNull($result->header('content-type'));
        }
    }

    /**
     * A dump shows the header names, never the body.
     *
     * @return void
     */
    public function testTheBodyNeverLeaves(): void
    {
        $result = FetchResult::fetched(200, ['Content-Type' => 'application/json'], '{"access_token":"the-token"}');

        self::assertSame(['status' => 'fetched', 'statusCode' => 200, 'headers' => ['content-type'], 'body' => '[redacted]', 'reason' => null], $result->__debugInfo());
        self::assertSame(['status' => 'failed', 'statusCode' => null, 'headers' => [], 'body' => null, 'reason' => 'fetch_failed'], FetchResult::failed()->__debugInfo());
        self::assertStringNotContainsString('the-token', print_r($result, true));
        self::assertStringNotContainsString('the-token', (string) json_encode($result));
    }

    /**
     * No dump, export or array cast reaches the body, yet the caller gets it
     * whole.
     *
     * @return void
     */
    public function testNoDumpExportOrArrayCastShowsTheBody(): void
    {
        $body   = '{"access_token":"the-token"}';
        $result = FetchResult::fetched(200, ['Content-Type' => 'application/json'], $body);

        foreach (self::shown($result) as $shown) {
            self::assertStringNotContainsString('the-token', $shown);
        }

        self::assertSame($body, $result->body());
        self::assertNull(FetchResult::failed()->body());
    }

    /**
     * It refuses to be serialised, so it cannot reach a queue or a cache.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Outbound responses cannot be serialised.');

        serialize(FetchResult::fetched(200, [], 'body'));
    }

    /**
     * It refuses to be unserialised, so a crafted payload cannot build one.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Outbound responses cannot be unserialised.');

        FetchResult::fetched(200, [], 'body')->__unserialize([]);
    }

    /**
     * How an object looks through VarDumper, `print_r()`, `var_export()` and an
     * array cast.
     *
     * @param  object  $value
     * @return list<string>
     */
    private static function shown(object $value): array
    {
        return [
            (string) (new CliDumper)->dump((new VarCloner)->cloneVar($value), true),
            print_r($value, true),
            var_export($value, true),
            print_r((array) $value, true),
            (string) json_encode((array) $value),
        ];
    }
}
