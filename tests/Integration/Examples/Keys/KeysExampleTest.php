<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Keys;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyStatus;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/keys.md` (SSO-2.5 to SSO-2.7, SSO-12.5), on the
 * shared example harness: an administrator rotates a SAML connection's signing
 * key without downtime (the first key made current at once, the next published
 * beside it, made current, and the old one retired), rotates the identity
 * provider's certificate (the new one trusted beside the old, the old one
 * distrusted), and lists the connection's keys. Each asserts what the change
 * answers, what it reports and what the connection holds after it: the new
 * provider's responses verify once its certificate is trusted, and the old
 * provider's are refused once its certificate is distrusted. The refusals the
 * guide lists are asserted beside them: a second `next` key, the current key
 * retired, a key retired twice, a certificate given twice or with its private
 * key, a stale caller and another tenant's connection, none of which writes or
 * reports anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyService::class)]
#[CoversClass(KeyResult::class)]
#[CoversClass(KeySummary::class)]
#[CoversClass(KeyRing::class)]
final class KeysExampleTest extends ExampleTestCase
{
    /** @var string The administrator's key. */
    private const string ADMINISTRATOR = 'admin-1';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The tenant's identity provider, signing with its first certificate. */
    private FakeSamlIdentityProvider $idp;

    /** @var string The SAML connection that trusts it. */
    private string $connectionId;

    /** @var \Tests\Integration\Examples\Keys\User The administrator acting. */
    private User $user;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the tenant's SAML connection, trusting the provider's certificate,
     * and the administrator.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->idp          = new FakeSamlIdentityProvider;
        $this->connectionId = $this->makeSamlConnection($this->idp);
        $this->user         = new User(['id' => self::ADMINISTRATOR]);
        $this->person       = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * The first signing key is generated and made current at once; the next is
     * added as `next` and published after the current one, and a second `next`
     * is refused; making it current leaves the old key retiring until the
     * overlap ends, and retiring that removes it. The current key is never
     * retired, and a key retired is gone. Each change asks `sso.keys.rotate`
     * and reports the administrator.
     *
     * @return void
     */
    public function testRotatingAServiceProviderKey(): void
    {
        $tenantId     = self::TENANT;
        $connectionId = $this->connectionId;
        $user         = $this->user;
        $events       = $this->recordKeyEvents();

        // @snippet-start keys-service
        $keys = app(KeyService::class);
        // @snippet-end keys-service
        $client  = Clients::browser();
        $request = self::requestOnSession('/admin/sso/keys');
        // @snippet-start keys-add-first
        $caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId());
        $result = $keys->addNext($tenantId, $connectionId, KeyUse::SP_SIGNING, $client, KeyType::RSA, $caller);

        $state = $result->key?->state; // KeyState::CURRENT
        // @snippet-end keys-add-first
        $first = self::keyOf($result->key);

        self::assertSame(KeyStatus::ADDED, $result->status);
        self::assertSame(KeyState::CURRENT, $state);
        self::assertSame([KeyType::RSA, 3072], [$first->type, $first->bits]);
        $this->freshness->assertAsked(FreshnessOperation::KEYS_ROTATE);

        $oldKeyId  = $first->id;
        $next      = self::keyOf($keys->addNext($tenantId, $connectionId, KeyUse::SP_SIGNING, Clients::browser(), caller: $caller)->key);
        $nextKeyId = $next->id;

        self::assertSame(KeyState::NEXT, $next->state);
        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $keys->addNext($tenantId, $connectionId, KeyUse::SP_SIGNING, Clients::browser(), caller: $caller)->reason);
        self::assertSame([$oldKeyId, $nextKeyId], self::idsOf(app(KeyRing::class)->published($connectionId, KeyUse::SP_SIGNING)));

        $client = Clients::browser();
        // @snippet-start keys-make-current
        $result = $keys->makeCurrent($tenantId, $connectionId, $nextKeyId, $client, $caller);

        $current  = $result->key;      // the new current key
        $previous = $result->previous; // the old one, now retiring, with retiringUntil set
        // @snippet-end keys-make-current
        $madeCurrent = self::keyOf($current);
        $retiring    = self::keyOf($previous);

        self::assertSame(KeyStatus::MADE_CURRENT, $result->status);
        self::assertSame([$nextKeyId, KeyState::CURRENT], [$madeCurrent->id, $madeCurrent->state]);
        self::assertSame([$oldKeyId, KeyState::RETIRING], [$retiring->id, $retiring->state]);
        self::assertSame('2026-11-08T09:30:00Z', $retiring->retiringUntil?->toIso8601ZuluString());
        self::assertSame([$nextKeyId], self::idsOf(app(KeyRing::class)->published($connectionId, KeyUse::SP_SIGNING)));

        $this->clock->advance(604800);

        $client = Clients::browser();
        // @snippet-start keys-retire
        $result = $keys->retire($tenantId, $connectionId, $oldKeyId, $client, $caller);
        // @snippet-end keys-retire
        self::assertSame(KeyStatus::RETIRED, $result->status);
        self::assertSame($oldKeyId, self::keyOf($result->key)->id);
        self::assertSame(FailureReason::KEY_NOT_FOUND, $keys->retire($tenantId, $connectionId, $oldKeyId, Clients::browser(), $caller)->reason);
        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $keys->retire($tenantId, $connectionId, $nextKeyId, Clients::browser(), $caller)->reason);
        self::assertSame([$nextKeyId], self::idsOf($keys->keys($tenantId, $connectionId) ?? [], KeyUse::SP_SIGNING));

        self::assertSame([
            ['KeyAdded', self::ADMINISTRATOR], ['KeyMadeCurrent', self::ADMINISTRATOR], ['KeyAdded', self::ADMINISTRATOR],
            ['KeyMadeCurrent', self::ADMINISTRATOR], ['KeyRetired', self::ADMINISTRATOR],
        ], $events->getArrayCopy());
    }

    /**
     * The provider's new certificate is trusted beside the old one, and the old
     * one then distrusted: the new provider's responses verify, and the old
     * provider's are refused for their signature. Trusting the same certificate
     * again, or one given with its private key, is invalid, and a certificate
     * distrusted is gone.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRotatingTheIdentityProvidersCertificate(): void
    {
        $tenantId         = self::TENANT;
        $connectionId     = $this->connectionId;
        $caller           = new Caller(new IdentityReference($this->user->getMorphClass(), (string) $this->user->getKey()));
        $keys             = app(KeyService::class);
        $rotated          = new FakeSamlIdentityProvider;
        $certificatePem   = $rotated->certificate();
        $oldCertificateId = $this->trustedCertificateIds()[0];

        $client = Clients::browser();
        // @snippet-start keys-trust-certificate
        $result = $keys->trustCertificate($tenantId, $connectionId, $certificatePem, $client, $caller);

        // Later, once the identity provider signs with the new certificate
        $removed = $keys->distrustCertificate($tenantId, $connectionId, $oldCertificateId, $client, $caller);
        // @snippet-end keys-trust-certificate
        self::assertSame(KeyStatus::TRUSTED, $result->status);
        self::assertSame([KeyUse::IDP_SIGNING, null], [$result->key?->use, $result->key?->state]);
        self::assertSame([KeyStatus::DISTRUSTED, $oldCertificateId], [$removed->status, $removed->key?->id]);
        self::assertSame([(string) $result->key?->id], $this->trustedCertificateIds());
        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);

        $this->linkThroughFlow($rotated, $connectionId, $this->person);

        $start    = $this->startFlow(Purpose::LINK, $connectionId, $this->person);
        $redirect = $this->respondAtProvider($this->idp, $connectionId, $start);

        self::assertFalse($redirect->hasCode());
        self::assertSame(FailureReason::SIGNATURE_INVALID->value, $redirect->error);

        [$privateKey, $certificate] = FakeSamlIdentityProvider::keyPair();

        $again   = $keys->trustCertificate($tenantId, $connectionId, $certificatePem, Clients::browser(), $caller);
        $withKey = $keys->trustCertificate($tenantId, $connectionId, $privateKey . $certificate, Clients::browser(), $caller);

        self::assertSame([FailureReason::SETTINGS_INVALID, [['certificate', 'duplicate']]], [$again->reason, self::violationsOf($again)]);
        self::assertSame([['certificate', 'private_key_refused']], self::violationsOf($withKey));
        self::assertSame(FailureReason::KEY_NOT_FOUND, $keys->distrustCertificate($tenantId, $connectionId, $oldCertificateId, Clients::browser(), $caller)->reason);
        self::assertSame([(string) $result->key?->id], $this->trustedCertificateIds());
    }

    /**
     * The connection's keys are listed by use, then current, next and the
     * certificates; none carries a private key, and another tenant's connection
     * answers `null`.
     *
     * @return void
     */
    public function testListingAConnectionsKeys(): void
    {
        $tenantId     = self::TENANT;
        $connectionId = $this->connectionId;
        $keys         = app(KeyService::class);
        $current      = (string) $keys->addNext($tenantId, $connectionId, KeyUse::SP_SIGNING, Clients::browser())->key?->id;
        $next         = (string) $keys->addNext($tenantId, $connectionId, KeyUse::SP_SIGNING, Clients::browser())->key?->id;

        // @snippet-start keys-list
        $summaries = $keys->keys($tenantId, $connectionId); // null when the tenant has no such connection
        // @snippet-end keys-list
        self::assertNotNull($summaries);
        self::assertSame(
            [[$current, KeyUse::SP_SIGNING, KeyState::CURRENT], [$next, KeyUse::SP_SIGNING, KeyState::NEXT], [$this->trustedCertificateIds()[0], KeyUse::IDP_SIGNING, null]],
            array_map(static fn (KeySummary $summary): array => [$summary->id, $summary->use, $summary->state], $summaries),
        );
        self::assertStringNotContainsString('PRIVATE KEY', (string) json_encode($summaries));
        self::assertNull($keys->keys('tenant-2', $connectionId));
    }

    /**
     * A change asked by a caller who did not authenticate recently enough, or
     * of another tenant's connection, is refused before anything is generated
     * or written, and reports nothing.
     *
     * @return void
     */
    public function testAChangeIsRefusedAndWritesNothing(): void
    {
        $keys        = app(KeyService::class);
        $certificate = FakeSamlIdentityProvider::keyPair()[1];
        $events      = $this->recordKeyEvents();
        $stale       = FakeFreshness::fresh()->staleFor(FreshnessOperation::KEYS_ROTATE, FreshnessOperation::CONNECTION_TRUST);

        $this->instance(Freshness::class, $stale);

        $added   = $keys->addNext(self::TENANT, $this->connectionId, KeyUse::SP_SIGNING, Clients::browser());
        $trusted = $keys->trustCertificate(self::TENANT, $this->connectionId, $certificate, Clients::browser());

        $stale->assertAskedExactly([FreshnessOperation::KEYS_ROTATE, FreshnessOperation::CONNECTION_TRUST]);
        self::assertTrue($added->isRefused());
        self::assertSame([FailureReason::FRESHNESS_REQUIRED, FailureReason::FRESHNESS_REQUIRED], [$added->reason, $trusted->reason]);

        $this->instance(Freshness::class, $this->freshness);

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $keys->addNext('tenant-2', $this->connectionId, KeyUse::SP_SIGNING, Clients::browser())->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $keys->trustCertificate('tenant-2', $this->connectionId, $certificate, Clients::browser())->reason);
        self::assertCount(1, $keys->keys(self::TENANT, $this->connectionId) ?? []);
        self::assertSame([], $events->getArrayCopy());
    }

    /**
     * Record each key event the package dispatches, as its short name and the
     * key of the administrator it names.
     *
     * @return \ArrayObject<int, array{0: string, 1: ?string}>
     */
    private function recordKeyEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: ?string}> $events */
        $events = new \ArrayObject;

        Event::listen([KeyAdded::class, KeyMadeCurrent::class, KeyRetired::class], static function (KeyAdded|KeyMadeCurrent|KeyRetired $event) use ($events): void {
            $events->append([class_basename($event), $event->context->actingIdentityId]);
        });

        return $events;
    }

    /**
     * The ids of the identity provider certificates the connection trusts, in
     * the order the package lists them.
     *
     * @return list<string>
     */
    private function trustedCertificateIds(): array
    {
        return self::idsOf(app(KeyService::class)->keys(self::TENANT, $this->connectionId) ?? [], KeyUse::IDP_SIGNING);
    }

    /**
     * The ids of the summaries, in order, of the use when one is given.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $summaries
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return list<string>
     */
    private static function idsOf(array $summaries, ?KeyUse $use = null): array
    {
        $matching = array_filter($summaries, static fn (KeySummary $summary): bool => $use === null || $summary->use === $use);

        return array_values(array_map(static fn (KeySummary $summary): string => $summary->id, $matching));
    }

    /**
     * The summary a result or another summary carries, which must be there.
     *
     * @param  ?\SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private static function keyOf(?KeySummary $key): KeySummary
    {
        self::assertNotNull($key);

        return $key;
    }

    /**
     * Each violation of the result, as its setting and its code.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyResult  $result
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(KeyResult $result): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $result->violations);
    }
}
