<?php

declare(strict_types = 1);

namespace Tests\Unit\Domains;

use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Domains\SystemDnsResolver;

/**
 * Unit tests for the default DNS resolver (SSO-3.2, decision D3): it asks for
 * the TXT records of the name, as absolute; an answer with none is `absent`; a
 * lookup that fails or warns is `lookup_failed`, logged with the name and never
 * a record; each record's character-strings are joined; and what it keeps is
 * capped. Every lookup is a stand-in, so no name is looked up over the network.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemDnsResolver::class)]
final class SystemDnsResolverTest extends TestCase
{
    /** @var \Monolog\Handler\TestHandler Where the resolver logs. */
    private TestHandler $handler;

    /**
     * Log to a handler of this test's own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->handler = new TestHandler;
    }

    /**
     * The resolver asks for the TXT records of the name as absolute, with a
     * trailing dot, so no search domain is ever tried in its place, and joins
     * each record's character-strings into one value.
     *
     * @return void
     */
    public function testAsksForTheTxtRecordsAndJoinsEachRecord(): void
    {
        $asked  = [];
        $lookup = $this->resolver(static function (string $name, int $type) use (&$asked): array {
            $asked[] = [$name, $type];

            return [
                ['host' => $name, 'type' => 'TXT', 'txt' => 'first', 'entries' => ['first']],
                ['host' => $name, 'type' => 'TXT', 'txt' => 'twohalves', 'entries' => ['two', 'halves']],
                ['host' => $name, 'type' => 'TXT', 'txt' => 'only-txt'],
            ];
        })->txt('_sso-verification.example.com');

        self::assertSame([['_sso-verification.example.com.', DNS_TXT]], $asked);
        self::assertTrue($lookup->isFound());
        self::assertSame(['first', 'twohalves', 'only-txt'], $lookup->records());
        self::assertSame([], $this->logged());
    }

    /**
     * An answer with no TXT record is `absent`, and so is one whose records are
     * all of another type or malformed.
     *
     * @return void
     */
    public function testAnAnswerWithNoTxtRecordIsAbsent(): void
    {
        self::assertTrue($this->resolver(static fn (): array => [])->txt('example.com')->isAbsent());

        $odd = $this->resolver(static fn (): array => [
            ['type' => 'CNAME', 'target' => 'elsewhere.example.com'],
            ['type' => 'TXT', 'entries' => [1, 2]],
            ['type' => 'TXT'],
            'not a record',
        ])->txt('example.com');

        self::assertTrue($odd->isAbsent());
    }

    /**
     * A lookup that answers `false`, or that warns whatever it answers, is
     * `lookup_failed`, never `absent`, and is logged with the name as given and
     * the warning only.
     *
     * @return void
     */
    public function testAFailedOrWarningLookupIsLookupFailed(): void
    {
        $failed = $this->resolver(static fn (): bool => false)->txt('example.com');

        $warned = $this->resolver(static function (): array {
            trigger_error('A temporary server error occurred.', E_USER_WARNING);

            return [['type' => 'TXT', 'txt' => 'secret-record']];
        })->txt('example.org');

        self::assertTrue($failed->isLookupFailed());
        self::assertTrue($warned->isLookupFailed());
        self::assertSame([
            ['warning', 'sso.dns.lookup_failed', ['name' => 'example.com', 'error' => 'no answer']],
            ['warning', 'sso.dns.lookup_failed', ['name' => 'example.org', 'error' => 'A temporary server error occurred. (severity 512)']],
        ], $this->logged());
        self::assertStringNotContainsString('secret-record', (string) json_encode($this->logged()));
    }

    /**
     * The handler that caught the warning is removed, so the application's own
     * is in place afterwards.
     *
     * @return void
     */
    public function testRestoresTheErrorHandler(): void
    {
        $handler = static fn (): bool => true;

        set_error_handler($handler);

        try {
            $this->resolver(static fn (): array => [])->txt('example.com');

            self::assertSame($handler, set_error_handler(null));
        } finally {
            restore_error_handler();
            restore_error_handler();
        }
    }

    /**
     * At most `MAX_RECORDS` records of at most `MAX_RECORD_LENGTH` bytes are
     * kept: a record of exactly that length is kept whole, and a longer one is
     * left out, not cut short.
     *
     * @return void
     */
    public function testCapsWhatItKeeps(): void
    {
        $overlong = str_repeat('x', SystemDnsResolver::MAX_RECORD_LENGTH + 1);
        $longest  = str_repeat('y', SystemDnsResolver::MAX_RECORD_LENGTH);
        $records  = [['type' => 'TXT', 'txt' => $overlong], ['type' => 'TXT', 'txt' => $longest]];

        for ($index = 0; $index < SystemDnsResolver::MAX_RECORDS + 4; $index++) {
            $records[] = ['type' => 'TXT', 'txt' => 'record-' . $index];
        }

        $kept = $this->resolver(static fn (): array => $records)->txt('example.com')->records();

        self::assertCount(SystemDnsResolver::MAX_RECORDS, $kept);
        self::assertSame($longest, $kept[0]);
        self::assertSame('record-0', $kept[1]);
        self::assertNotContains($overlong, $kept);
    }

    /**
     * An empty name is the caller's mistake.
     *
     * @return void
     */
    public function testAnEmptyNameIsAnInvalidArgument(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->resolver(static fn (): array => [])->txt('');
    }

    /**
     * A resolver whose lookup is the closure, logging to this test's handler.
     *
     * @param  \Closure(string, int): mixed  $lookup
     * @return \SineMacula\Laravel\Sso\Domains\SystemDnsResolver
     */
    private function resolver(\Closure $lookup): SystemDnsResolver
    {
        return new SystemDnsResolver(new Logger('dns', [$this->handler]), $lookup);
    }

    /**
     * Each entry logged, as its level, message and context.
     *
     * @return list<array{string, string, array<array-key, mixed>}>
     */
    private function logged(): array
    {
        $entry = static fn (LogRecord $record): array => [strtolower($record->level->getName()), $record->message, $record->context];

        return array_values(array_map($entry, $this->handler->getRecords()));
    }
}
