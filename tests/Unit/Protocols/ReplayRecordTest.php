<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\Reinitiation;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Unit tests for what a driver asks the completion to record against replay
 * (SSO-6.6): a SAML assertion's versioned, length-prefixed key, so no choice of
 * values makes two tuples share one; the expiry kept as given; a dump that
 * never shows the key; the completion carrying it; and re-initiation's two
 * outcomes (SSO-5.8).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReplayRecord::class)]
#[CoversClass(Reinitiation::class)]
#[CoversClass(Completion::class)]
final class ReplayRecordTest extends TestCase
{
    /**
     * A SAML assertion's key is the version, then each part as its length in
     * bytes, a colon and the part, in the namespace for assertions, until the
     * moment given.
     *
     * @return void
     */
    public function testEncodesASamlAssertionsKey(): void
    {
        $until  = CarbonImmutable::parse('2026-11-01T12:05:00Z');
        $record = ReplayRecord::samlAssertion('01jbconnection000000000000', 'https://idp.example.com', '_a1', $until);

        self::assertSame('saml_assertion', ReplayRecord::SAML_ASSERTION);
        self::assertSame('saml_assertion', $record->namespace);
        self::assertSame('v1|26:01jbconnection000000000000|23:https://idp.example.com|3:_a1', $record->key());
        self::assertSame($until, $record->until);
        self::assertSame('v1|2:é|1:x|1:y', ReplayRecord::samlAssertion('é', 'x', 'y', $until)->key());
    }

    /**
     * Rows of `[one, other]`: two tuples a naive join would make one key.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>}>
     */
    public static function provideAmbiguousTuples(): iterable
    {
        yield from [
            'a separator moved' => [['a|b', 'c', 'd'], ['a', 'b|c', 'd']],
            'a length forged'   => [['a', '1:b', 'c'], ['a|1:1', 'b', 'c']],
            'a colon moved'     => [['a:', 'b', 'c'], ['a', ':b', 'c']],
        ];
    }

    /**
     * Two different tuples never share a key.
     *
     * @param  list<string>  $one
     * @param  list<string>  $other
     * @return void
     */
    #[DataProvider('provideAmbiguousTuples')]
    public function testDifferentTuplesNeverShareAKey(array $one, array $other): void
    {
        $until = CarbonImmutable::parse('2026-11-01T12:05:00Z');

        self::assertNotSame(ReplayRecord::samlAssertion(...[...$one, $until])->key(), ReplayRecord::samlAssertion(...[...$other, $until])->key());
    }

    /**
     * Rows of `[connection, issuer, id]`: a part left empty.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideEmptyParts(): iterable
    {
        yield from [
            'no connection' => ['', 'issuer', 'id'],
            'no issuer'     => ['connection', '', 'id'],
            'no id'         => ['connection', 'issuer', ''],
        ];
    }

    /**
     * Each part must be non-empty.
     *
     * @param  string  $connection
     * @param  string  $issuer
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideEmptyParts')]
    public function testEachPartMustBeGiven(string $connection, string $issuer, string $id): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('An assertion is recorded by a non-empty connection, issuer and id.'));

        ReplayRecord::samlAssertion($connection, $issuer, $id, CarbonImmutable::now());
    }

    /**
     * A dump shows the namespace and the expiry, never the key.
     *
     * @return void
     */
    public function testNeverShowsItsKey(): void
    {
        $record = self::record();

        self::assertSame(['namespace' => 'saml_assertion', 'key' => '[redacted]', 'until' => '2026-11-01T12:05:00+00:00'], $record->__debugInfo());
        self::assertStringNotContainsString('_assertion-id', print_r($record, true));
    }

    /**
     * The record refuses to be serialised.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A replay record cannot be serialised.'));

        serialize(self::record());
    }

    /**
     * The record refuses to be unserialised.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A replay record cannot be unserialised.'));

        self::record()->__unserialize([]);
    }

    /**
     * A verified completion carries the record it was given, and none unless
     * given; a refused one carries none.
     *
     * @return void
     */
    public function testACompletionCarriesItsRecord(): void
    {
        $record = ReplayRecord::samlAssertion('connection', 'issuer', 'id', CarbonImmutable::now());

        self::assertSame($record, Completion::verified(VerifyingDriver::claims(), $record)->replay);
        self::assertNull(Completion::verified(VerifyingDriver::claims())->replay);
        self::assertNull(Completion::refused(FailureReason::REPLAYED)->replay);
    }

    /**
     * Re-initiation is allowed to an absolute https start URL with its record,
     * or refused with a reason.
     *
     * @return void
     */
    public function testReinitiationIsAllowedOrRefused(): void
    {
        $record  = ReplayRecord::samlAssertion('connection', 'issuer', 'id', CarbonImmutable::now());
        $allowed = Reinitiation::allowed('HTTPS://app.example.com/start?connection=1', $record);
        $refused = Reinitiation::refused(FailureReason::UNSOLICITED_NOT_ALLOWED);

        self::assertSame([true, 'HTTPS://app.example.com/start?connection=1', $record, null], [$allowed->isAllowed(), $allowed->startUrl, $allowed->replay, $allowed->reason]);
        self::assertSame([false, null, null, FailureReason::UNSOLICITED_NOT_ALLOWED], [$refused->isAllowed(), $refused->startUrl, $refused->replay, $refused->reason]);
    }

    /**
     * Rows of `[url]`: a start URL that is not absolute https.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedStartUrls(): iterable
    {
        yield from [
            'http'     => ['http://app.example.com/start'],
            'relative' => ['/start'],
            'empty'    => [''],
        ];
    }

    /**
     * Re-initiation never leads anywhere but an absolute https URL.
     *
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideRefusedStartUrls')]
    public function testReinitiationLeadsOnlyToHttps(string $url): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('A re-initiation leads to an absolute https URL.'));

        Reinitiation::allowed($url, ReplayRecord::samlAssertion('connection', 'issuer', 'id', CarbonImmutable::now()));
    }

    /**
     * A record of an assertion, for the redaction tests.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ReplayRecord
     */
    private static function record(): ReplayRecord
    {
        return ReplayRecord::samlAssertion('connection', 'issuer', '_assertion-id', CarbonImmutable::parse('2026-11-01T12:05:00Z'));
    }
}
