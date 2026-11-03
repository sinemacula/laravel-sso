<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\UniqueConstraintViolationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Casts\BinaryString;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the link, authorisation request and handoff code models
 * (SSO-8.4, SSO-5.1, SSO-9.2, SSO-11.10): their tables and casts, their keys
 * and clock stamps, what is hidden from serialisation, a link's subject kept
 * byte for byte and its fixed parts, and the uniqueness each table enforces.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Link::class)]
#[CoversClass(AuthorizationRequest::class)]
#[CoversClass(HandoffCode::class)]
#[CoversClass(BinaryString::class)]
final class FlowModelsTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /**
     * Bind a fixed clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->createConnectionTables();
        $this->createFlowTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Each model lives in its configured table on the storage connection.
     *
     * @return void
     */
    public function testEachLivesInItsConfiguredTable(): void
    {
        self::assertSame('sso_links', (new Link)->getTable());
        self::assertSame('sso_authorization_requests', (new AuthorizationRequest)->getTable());
        self::assertSame('sso_handoff_codes', (new HandoffCode)->getTable());

        config()->set('sso.links.table', 'idp_links');
        config()->set('sso.authorization_requests.table', 'idp_requests');
        config()->set('sso.handoff_codes.table', 'idp_codes');

        try {
            self::assertSame('idp_links', (new Link)->getTable());
            self::assertSame('idp_requests', (new AuthorizationRequest)->getTable());
            self::assertSame('idp_codes', (new HandoffCode)->getTable());
        } finally {
            // Put the names back, so tearDown drops the tables setUp created
            // rather than leaving them for the next test on a real database.
            config()->set('sso.links.table', 'sso_links');
            config()->set('sso.authorization_requests.table', 'sso_authorization_requests');
            config()->set('sso.handoff_codes.table', 'sso_handoff_codes');
        }
    }

    /**
     * A request is keyed, stamped and cast; its digests and verifier are
     * hidden.
     *
     * @return void
     */
    public function testAnAuthorizationRequest(): void
    {
        $request = $this->makeAuthorizationRequest($this->makeConnection(), [
            'purpose'       => Purpose::LINK,
            'identity_type' => 'user',
            'identity_id'   => '7',
            'code_verifier' => 'cipher',
        ]);
        $read = AuthorizationRequest::query()->findOrFail($request->id);

        self::assertMatchesRegularExpression('/^[0-9a-z]{26}$/', $read->id);
        self::assertSame(Purpose::LINK, $read->purpose);
        self::assertFalse($read->issuer_required);
        self::assertSame('2026-11-01T09:40:00+00:00', $read->expires_at->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', $read->created_at->toIso8601String());
        self::assertNull($read->consumed_at);
        self::assertNull($read->voided_at);
        self::assertNull($read->completed_at);
        self::assertSame('user', $read->identity_type);
        self::assertSame('7', $read->identity_id);
        self::assertNull($read->session_id);
        self::assertSame([], array_intersect(['state_digest', 'nonce_digest', 'code_verifier'], array_keys($read->toArray())));
    }

    /**
     * A code is keyed, stamped and cast; its digest and result are hidden.
     *
     * @return void
     */
    public function testAHandoffCode(): void
    {
        $code = $this->makeHandoffCode($this->makeConnection(), [
            'purpose'              => Purpose::REAUTHENTICATE,
            'identity_type'        => 'user',
            'identity_id'          => '7',
            'session_id'           => 'session-1',
            'linked_identity_type' => 'user',
            'linked_identity_id'   => '8',
            'session_not_after'    => CarbonImmutable::parse('2026-11-01T18:00:00Z'),
            'trust_version'        => '4',
        ]);

        $read = HandoffCode::query()->findOrFail($code->id);

        self::assertSame(Purpose::REAUTHENTICATE, $read->purpose);
        self::assertSame('7', $read->identity_id);
        self::assertSame('8', $read->linked_identity_id);
        self::assertSame('session-1', $read->session_id);
        self::assertSame(4, $read->trust_version);
        self::assertSame('2026-11-01T18:00:00+00:00', $read->session_not_after?->toIso8601String());
        self::assertSame('2026-11-01T09:31:00+00:00', $read->expires_at->toIso8601String());
        self::assertNull($read->redeemed_at);
        self::assertNull($read->voided_at);
        self::assertSame([], array_intersect(['code_digest', 'result'], array_keys($read->toArray())));
    }

    /**
     * A link keeps its subject byte for byte, invalid UTF-8, trailing spaces
     * and backslashes included, and is active with no provenance by default.
     *
     * @return void
     */
    public function testALinkKeepsItsSubjectByteForByte(): void
    {
        $subject = "Sub\\ject \xff\x00 ";
        $link    = $this->makeLink($this->makeConnection(), $subject);
        $read    = Link::query()->findOrFail($link->id);

        self::assertSame($subject, $read->subject);
        self::assertSame(LinkState::ACTIVE, $read->state);
        self::assertFalse($read->domain_provenance);
        self::assertNull($read->reservation_expires_at);
        self::assertNull($read->last_used_at);
        self::assertSame('user', $read->identity_type);
        self::assertSame('1', $read->identity_id);

        $read->forceFill(['state' => LinkState::RESERVED, 'last_used_at' => CarbonImmutable::parse('2026-11-01T10:00:00Z')])->save();

        self::assertSame(LinkState::RESERVED, Link::query()->findOrFail($link->id)->state);
        self::assertSame($subject, Link::query()->findOrFail($link->id)->subject);
    }

    /**
     * Rows of `[column, value]`: what a link links, and a change to it.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideFixedColumns(): iterable
    {
        yield 'the issuer' => ['issuer', 'https://other.example.com'];
        yield 'the subject' => ['subject', 'subject-2'];
        yield 'the key' => ['subject_key', str_repeat('0', 64)];
        yield 'the NameID format' => ['name_id_format', 'format'];
        yield 'the connection' => ['connection_id', '01jbotherconnection0000000'];
    }

    /**
     * What a link links is fixed once it exists.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideFixedColumns')]
    public function testWhatALinkLinksIsFixed(string $column, string $value): void
    {
        $link = $this->makeLink($this->makeConnection());

        $this->expectExceptionObject(new \LogicException('A link\'s connection, issuer, NameID format and subject are fixed when it is made.'));

        $link->forceFill([$column => $value])->save();
    }

    /**
     * One subject is linked once per connection, however it is written; the
     * same subject may be linked through another connection.
     *
     * @return void
     */
    public function testOneSubjectIsLinkedOncePerConnection(): void
    {
        $connection = $this->makeConnection();
        $other      = $this->makeConnection();

        $this->makeLink($connection);
        $this->makeLink($other);

        $this->expectException(UniqueConstraintViolationException::class);

        $this->makeLink($connection, 'subject-1', ['identity_id' => '2']);
    }

    /**
     * Rows of `[column]`: what a request is found by.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRequestIdentifiers(): iterable
    {
        yield 'the reference' => ['reference'];
        yield 'the state\'s digest' => ['state_digest'];
        yield 'the SAML request id' => ['saml_request_id'];
    }

    /**
     * A reference, a state's digest, and a SAML request id within a connection
     * are each held once; a SAML request id may repeat in another connection,
     * and requests with none are many.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideRequestIdentifiers')]
    public function testARequestsIdentifierIsHeldOnce(string $column): void
    {
        $connection = $this->makeConnection();
        $request    = $this->makeAuthorizationRequest($connection, ['saml_request_id' => '_id-1']);

        $this->makeAuthorizationRequest($this->makeConnection(), ['saml_request_id' => '_id-1']);
        $this->makeAuthorizationRequest($connection);
        $this->makeAuthorizationRequest($connection);

        $this->expectException(UniqueConstraintViolationException::class);

        $this->makeAuthorizationRequest($connection, [$column => $request->getAttribute($column)]);
    }

    /**
     * A code's digest is held once.
     *
     * @return void
     */
    public function testACodesDigestIsHeldOnce(): void
    {
        $connection = $this->makeConnection();
        $code       = $this->makeHandoffCode($connection);

        $this->expectException(UniqueConstraintViolationException::class);

        $this->makeHandoffCode($connection, ['code_digest' => $code->code_digest]);
    }
}
