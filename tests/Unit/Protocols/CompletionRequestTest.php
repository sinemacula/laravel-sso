<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for what arrived at a completion endpoint: the method, the raw
 * query string and the posted fields, never shown in a dump and never
 * serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionRequest::class)]
final class CompletionRequestTest extends TestCase
{
    /**
     * A GET keeps its raw query string, repeated parameters included, which a
     * parsed query would hide.
     *
     * @return void
     */
    public function testAGetKeepsTheRawQueryString(): void
    {
        $request = CompletionRequest::fromRequest(Request::create('https://api.example.com/callback?code=a&state=b&state=c', 'get'));

        self::assertSame('GET', $request->method);
        self::assertSame('code=a&state=b&state=c', $request->query());
        self::assertSame([], $request->body());
    }

    /**
     * A POST keeps its form fields.
     *
     * @return void
     */
    public function testAPostKeepsItsFormFields(): void
    {
        $request = CompletionRequest::fromRequest(Request::create('https://api.example.com/assertions', 'POST', ['SAMLResponse' => 'PHNhbWw+', 'RelayState' => 'r']));

        self::assertSame('POST', $request->method);
        self::assertSame('', $request->query());
        self::assertSame(['SAMLResponse' => 'PHNhbWw+', 'RelayState' => 'r'], $request->body());
    }

    /**
     * A dump shows the method and the names of the fields, never a value.
     *
     * @return void
     */
    public function testADumpShowsNoValue(): void
    {
        $request = new CompletionRequest('POST', 'code=secret-code', ['SAMLResponse' => 'secret-assertion']);

        $dump = print_r($request, true);

        self::assertStringNotContainsString('secret', $dump);
        self::assertSame(['method' => 'POST', 'query' => '[redacted]', 'body' => ['SAMLResponse']], $request->__debugInfo());
    }

    /**
     * Neither the dumper behind Laravel's `dump()` (which also lists private
     * properties), an export, an array cast nor JSON encoding shows the query
     * string or a posted value.
     *
     * @return void
     */
    public function testNoDumpOrEncodingShowsAValue(): void
    {
        $request = new CompletionRequest('POST', 'code=secret-code', ['SAMLResponse' => 'secret-assertion']);
        $dumped  = (string) (new CliDumper)->dump((new VarCloner)->cloneVar($request), true);

        self::assertStringNotContainsString('secret-', $dumped);
        self::assertStringNotContainsString('secret-', var_export($request, true));
        self::assertStringNotContainsString('secret-', (string) json_encode((array) $request));
        self::assertSame('{"method":"POST","query":"[redacted]","body":["SAMLResponse"]}', json_encode($request));
        self::assertSame('code=secret-code', $request->query());
        self::assertSame(['SAMLResponse' => 'secret-assertion'], $request->body());
    }

    /**
     * It refuses to be serialised.
     *
     * @return void
     */
    public function testItRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A completion request cannot be serialised.');

        serialize(new CompletionRequest('GET', 'code=a', []));
    }

    /**
     * It refuses to be unserialised.
     *
     * @return void
     */
    public function testItRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A completion request cannot be unserialised.');

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(CompletionRequest::class), CompletionRequest::class));
    }
}
