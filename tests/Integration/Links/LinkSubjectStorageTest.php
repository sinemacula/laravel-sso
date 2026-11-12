<?php

declare(strict_types = 1);

namespace Tests\Integration\Links;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Results\ExampleResults;
use Tests\TestCase;

/**
 * Integration tests that subjects are stored and matched byte for byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkSubject::class)]
final class LinkSubjectStorageTest extends TestCase
{
    use UsesConnections;

    /** @var string The issuer every subject is from. */
    private const string ISSUER = 'https://idp.example.com';

    /** @var list<string> Subjects that a lossy column would change, or fold together. */
    private const array SUBJECTS = [
        "\xC3\x28 invalid UTF-8 \xFF",
        "nul\x00byte",
        'back\slash',
        'escape\x00\377',
        'subject ',
        'subject',
        'Subject',
        'SUBJECT',
    ];

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the subjects are linked through. */
    private Connection $connection;

    /**
     * Bind a fixed clock and create a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['enabled' => true]);
    }

    /**
     * Each subject round-trips byte for byte and resolves to its own identity.
     *
     * @return void
     */
    public function testEachSubjectRoundTripsAndStaysDistinct(): void
    {
        foreach (self::SUBJECTS as $index => $subject) {
            $identity = new IdentityReference('user', (string) $index);
            $creation = $this->store()->create($this->connection, new LinkSubject(self::ISSUER, $subject), $identity, LinkOrigin::LINK_PURPOSE, Clients::browser());

            self::assertTrue($creation->isCreated(), bin2hex($subject));
        }

        self::assertSame(count(self::SUBJECTS), Link::query()->count());

        foreach (self::SUBJECTS as $index => $subject) {

            $key  = (new LinkSubject(self::ISSUER, $subject))->key();
            $link = Link::query()->where('subject_key', $key)->sole();

            self::assertSame(bin2hex($subject), bin2hex($link->subject));
            self::assertSame((string) $index, $link->identity_id);

            $resolved = $this->store()->resolve($this->resultFor($subject), Clients::browser());

            self::assertSame(['user', (string) $index], [$resolved->identity?->type, $resolved->identity?->id], bin2hex($subject));
        }
    }

    /**
     * An exact duplicate is refused while each near neighbour was linked.
     *
     * @return void
     */
    public function testTheSameBytesAreLinkedOnce(): void
    {
        foreach (self::SUBJECTS as $index => $subject) {
            $this->store()->create(
                $this->connection,
                new LinkSubject(self::ISSUER, $subject),
                new IdentityReference('user', (string) $index),
                LinkOrigin::LINK_PURPOSE,
                Clients::browser(),
            );
        }

        foreach (self::SUBJECTS as $subject) {

            $creation = $this->store()->create(
                $this->connection,
                new LinkSubject(self::ISSUER, $subject),
                new IdentityReference('user', 'another'),
                LinkOrigin::LINK_PURPOSE,
                Clients::browser(),
            );

            self::assertSame('subject_already_linked', $creation->status->value, bin2hex($subject));
        }

        self::assertSame(count(self::SUBJECTS), Link::query()->count());
    }

    /**
     * A verified result through the connection with the subject given.
     *
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function resultFor(string $subject): VerifiedResult
    {
        return new VerifiedResult(
            self::ISSUER,
            $subject,
            null,
            $this->connection->id,
            $this->connection->tenant_id,
            $this->connection->protocol,
            'web',
            Purpose::SIGN_IN,
            RequestReference::fromString(ExampleResults::REFERENCE),
            [],
            false,
            new AuthenticationContext,
        );
    }

    /**
     * The link store, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkStore
     */
    private function store(): LinkStore
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(LinkStore::class);
    }
}
