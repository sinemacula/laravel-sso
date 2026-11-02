<?php

declare(strict_types = 1);

namespace Tests\Unit\Results;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\ProviderDeadlineLimitsSession;
use SineMacula\Laravel\Sso\Results\StoredValues;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Unit tests for the parts of a verified result: the authentication context and
 * its bounds, the linking email and its form, the claims a driver verified,
 * kept out of dumps and serialisation, each part's JSON showing no provider
 * value, the default deadline answer, and the stable values of their enums.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContext::class)]
#[CoversClass(LinkingEmail::class)]
#[CoversClass(VerifiedClaims::class)]
#[CoversClass(StoredValues::class)]
#[CoversClass(ProviderDeadlineLimitsSession::class)]
#[CoversClass(DeadlineEffect::class)]
#[CoversClass(LinkingEmailSource::class)]
final class ResultPartsTest extends TestCase
{
    /**
     * An empty context states nothing; a full one keeps every part and stores
     * its instants in UTC to the microsecond.
     *
     * @return void
     */
    public function testTheAuthenticationContext(): void
    {
        $empty = new AuthenticationContext;

        self::assertSame([
            'authenticated_at'          => null,
            'methods'                   => [],
            'context_class'             => null,
            'provider_session_id'       => null,
            'provider_session_deadline' => null,
        ], $empty->toArray());

        $context = new AuthenticationContext(CarbonImmutable::parse('2026-11-01T12:00:00.5+02:00'), ['pwd'], 'acr', 'sid', CarbonImmutable::parse('2026-11-02T00:00:00Z'));

        self::assertSame([
            'authenticated_at'          => '2026-11-01T10:00:00.500000Z',
            'methods'                   => ['pwd'],
            'context_class'             => 'acr',
            'provider_session_id'       => 'sid',
            'provider_session_deadline' => '2026-11-02T00:00:00.000000Z',
        ], $context->toArray());
        self::assertSame($context->toArray(), AuthenticationContext::restore($context->toArray())->toArray());
        self::assertSame(32, AuthenticationContext::MAX_METHODS);
        self::assertSame(255, AuthenticationContext::MAX_METHOD_LENGTH);
        self::assertSame(1024, AuthenticationContext::MAX_VALUE_LENGTH);
    }

    /**
     * The context keeps at most 32 methods, each 1 to 255 bytes, in a list, and
     * a class and session id of 1 to 1024 bytes.
     *
     * @return void
     */
    public function testTheAuthenticationContextsBounds(): void
    {
        self::assertCount(32, (new AuthenticationContext(methods: array_fill(0, 32, str_repeat('m', 255))))->methods);
        self::assertSame(str_repeat('c', 1024), (new AuthenticationContext(contextClass: str_repeat('c', 1024)))->contextClass);

        $messages = [];

        $malformed = [
            ['methods' => array_fill(0, 33, 'pwd')],
            ['methods' => ['a' => 'pwd']],
            ['methods' => [1]],
            ['methods' => ['']],
            ['methods' => [str_repeat('m', 256)]],
            ['contextClass' => str_repeat('c', 1025)],
            ['contextClass' => ''],
            ['providerSessionId' => str_repeat('s', 1025)],
        ];

        foreach ($malformed as $arguments) {
            try {
                new AuthenticationContext(...$arguments); // @phpstan-ignore argument.type
                $messages[] = 'accepted';
            } catch (\InvalidArgumentException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        self::assertSame([
            'A verified result keeps a list of at most 32 authentication methods.',
            'A verified result keeps a list of at most 32 authentication methods.',
            'Each authentication method is a string.',
            'A verified result\'s authentication method is 1 to 255 bytes.',
            'A verified result\'s authentication method is 1 to 255 bytes.',
            'A verified result\'s authentication context class is 1 to 1024 bytes.',
            'A verified result\'s authentication context class is 1 to 1024 bytes.',
            'A verified result\'s provider session id is 1 to 1024 bytes.',
        ], $messages);
    }

    /**
     * A linking email keeps its email, source and organisation exactly, gives
     * its domain after the last `@`, and refuses anything without one `@`
     * between two non-empty parts.
     *
     * @return void
     */
    public function testTheLinkingEmail(): void
    {
        $email = new LinkingEmail('Person+Tag@Example.COM', LinkingEmailSource::ID_TOKEN);

        self::assertSame('Example.COM', $email->domain());
        self::assertSame(['email' => 'Person+Tag@Example.COM', 'source' => 'id_token', 'organization' => null], $email->toArray());
        self::assertSame($email->toArray(), LinkingEmail::restore($email->toArray())->toArray());
        self::assertSame(320, LinkingEmail::MAX_EMAIL_LENGTH);
        self::assertSame(255, LinkingEmail::MAX_ORGANIZATION_LENGTH);
        self::assertSame(320, strlen((new LinkingEmail(str_repeat('a', 64) . '@' . str_repeat('d', 255), LinkingEmailSource::USERINFO, str_repeat('o', 255)))->email));

        $messages = [];

        $emails = [['person'], ['@example.com'], ['person@'], ['a@b@c'], [''], [str_repeat('a', 64) . '@' . str_repeat('d', 256)], ['a@b', str_repeat('o', 256)], ['a@b', '']];

        foreach ($emails as $arguments) {
            try {
                new LinkingEmail($arguments[0], LinkingEmailSource::SAML_ATTRIBUTE, $arguments[1] ?? null);
                $messages[] = 'accepted';
            } catch (\InvalidArgumentException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        self::assertSame([
            'A linking email has one `@` between a local part and a domain.',
            'A linking email has one `@` between a local part and a domain.',
            'A linking email has one `@` between a local part and a domain.',
            'A linking email has one `@` between a local part and a domain.',
            'A verified result\'s linking email is 1 to 320 bytes.',
            'A verified result\'s linking email is 1 to 320 bytes.',
            'A verified result\'s organisation is 1 to 255 bytes.',
            'A verified result\'s organisation is 1 to 255 bytes.',
        ], $messages);
    }

    /**
     * Claims keep what the driver verified exactly; a dump shows the issuer,
     * the format and the attributes' names, never the subject or a value.
     *
     * @return void
     */
    public function testTheClaims(): void
    {
        $claims = ExampleResults::claims();

        self::assertSame('Subject 1 ', $claims->subject);
        self::assertSame(['mail' => ['person@example.com'], 'memberOf' => ['staff']], $claims->attributes);
        self::assertNull($claims->linkingEmail);
        self::assertSame([
            'issuer'         => 'https://idp.example.com',
            'subject'        => '[redacted]',
            'name_id_format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'attributes'     => ['mail', 'memberOf'],
        ], $claims->__debugInfo());
        self::assertStringNotContainsString('person@example.com', print_r($claims, true));

        $this->expectExceptionObject(new \InvalidArgumentException('A verified result\'s subject is 1 to 1024 bytes.'));

        new VerifiedClaims('https://idp.example.com', str_repeat('s', 1025), null, [], new AuthenticationContext);
    }

    /**
     * A context's JSON shows which parts were stated, each `[redacted]`, and
     * how many methods, never a value: an empty one states nothing.
     *
     * @return void
     */
    public function testTheAuthenticationContextsJsonShowsNoValue(): void
    {
        self::assertSame([
            'authenticated_at'          => null,
            'methods'                   => 0,
            'context_class'             => null,
            'provider_session_id'       => null,
            'provider_session_deadline' => null,
        ], (new AuthenticationContext)->jsonSerialize());
        self::assertSame(
            '{"authenticated_at":"[redacted]","methods":2,"context_class":"[redacted]","provider_session_id":"[redacted]","provider_session_deadline":"[redacted]"}',
            json_encode(ExampleResults::context()),
        );
    }

    /**
     * A linking email's JSON shows its source, and its email and organisation
     * as `[redacted]`, the organisation `null` when none was given.
     *
     * @return void
     */
    public function testTheLinkingEmailsJsonShowsNoValue(): void
    {
        self::assertSame(
            '{"email":"[redacted]","source":"saml_attribute","organization":"[redacted]"}',
            json_encode(new LinkingEmail('person@example.com', LinkingEmailSource::SAML_ATTRIBUTE, 'example-org')),
        );
        $email = new LinkingEmail('person@example.com', LinkingEmailSource::ID_TOKEN);

        self::assertSame(['email' => '[redacted]', 'source' => 'id_token', 'organization' => null], $email->jsonSerialize());
    }

    /**
     * Claims' JSON shows the issuer, the format, each attribute's name with the
     * kind of its value, and the redacted context and linking email, never the
     * subject or a value the provider asserted.
     *
     * @return void
     */
    public function testTheClaimsJsonShowsNoProviderValue(): void
    {
        self::assertSame(
            '{"issuer":"https:\/\/idp.example.com","subject":"[redacted]","name_id_format":"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",'
            . '"attributes":{"mail":"array","memberOf":"array"},"authentication_context":{"authenticated_at":"[redacted]","methods":2,"context_class":"[redacted]",'
            . '"provider_session_id":"[redacted]","provider_session_deadline":"[redacted]"},"linking_email":null}',
            json_encode(ExampleResults::claims()),
        );

        $claims = new VerifiedClaims(
            'https://op.example.com',
            'sub-1',
            null,
            ['email' => 'person@example.com', 'age' => 42, 'verified' => true, 'nickname' => null],
            new AuthenticationContext,
            new LinkingEmail('person@example.com', LinkingEmailSource::ID_TOKEN),
        );

        self::assertSame([
            'issuer'                 => 'https://op.example.com',
            'subject'                => '[redacted]',
            'name_id_format'         => null,
            'attributes'             => ['email' => 'string', 'age' => 'int', 'verified' => 'bool', 'nickname' => 'null'],
            'authentication_context' => (new AuthenticationContext)->jsonSerialize(),
            'linking_email'          => ['email' => '[redacted]', 'source' => 'id_token', 'organization' => null],
        ], $claims->jsonSerialize());
        self::assertStringNotContainsString('person@example.com', (string) json_encode($claims));
        self::assertStringNotContainsString('sub-1', (string) json_encode($claims));
    }

    /**
     * Claims cannot be serialised.
     *
     * @return void
     */
    public function testClaimsCannotBeSerialized(): void
    {
        $this->expectExceptionObject(new \LogicException('Verified claims cannot be serialised.'));

        serialize(ExampleResults::claims());
    }

    /**
     * Claims cannot be unserialised.
     *
     * @return void
     */
    public function testClaimsCannotBeUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('Verified claims cannot be unserialised.'));

        unserialize('O:45:"SineMacula\Laravel\Sso\Results\VerifiedClaims":0:{}');
    }

    /**
     * Claims bound their issuer and NameID format as a result does.
     *
     * @return void
     */
    public function testTheClaimsBounds(): void
    {
        $messages = [];

        foreach ([['', 's', null], [str_repeat('i', 1025), 's', null], ['i', '', null], ['i', 's', ''], ['i', 's', str_repeat('f', 256)]] as [$issuer, $subject, $format]) {
            try {
                new VerifiedClaims($issuer, $subject, $format, [], new AuthenticationContext);
                $messages[] = 'accepted';
            } catch (\InvalidArgumentException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        self::assertSame([
            'A verified result\'s issuer is 1 to 1024 bytes.',
            'A verified result\'s issuer is 1 to 1024 bytes.',
            'A verified result\'s subject is 1 to 1024 bytes.',
            'A verified result\'s NameID format is 1 to 255 bytes.',
            'A verified result\'s NameID format is 1 to 255 bytes.',
        ], $messages);
    }

    /**
     * The default deadline contract says the deadline limits the session; the
     * enums' values are stable.
     *
     * @return void
     */
    public function testTheDeadlineAndTheEnums(): void
    {
        self::assertSame(DeadlineEffect::LIMITS_SESSION, (new ProviderDeadlineLimitsSession)->effect(ExampleResults::bare()));
        self::assertTrue(DeadlineEffect::LIMITS_SESSION->limitsSession());
        self::assertFalse(DeadlineEffect::IGNORED->limitsSession());
        self::assertSame(['limits_session', 'ignored'], array_column(DeadlineEffect::cases(), 'value'));
        self::assertSame(['id_token', 'userinfo', 'saml_attribute'], array_column(LinkingEmailSource::cases(), 'value'));
    }

    /**
     * Stored values are read strictly: a string is a string, an optional one
     * may be absent, and an instant is exactly the stored form.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadsStoredValuesStrictly(): void
    {
        $throwing = static fn (\Throwable $error): \Closure => static fn (): never => throw $error;

        self::assertSame('Y-m-d\TH:i:s.u\Z', StoredValues::INSTANT_FORMAT);
        self::assertSame('[redacted]', StoredValues::REDACTED);
        self::assertNull(StoredValues::redacted(null));
        self::assertSame('[redacted]', StoredValues::redacted('a'));
        self::assertSame('[redacted]', StoredValues::redacted(''));
        self::assertSame('[redacted]', StoredValues::redacted(0));
        self::assertSame('a', StoredValues::string(['k' => 'a'], 'k'));
        self::assertNull(StoredValues::optionalString([], 'k'));
        self::assertNull(StoredValues::optionalString(['k' => null], 'k'));
        self::assertSame('', StoredValues::optionalString(['k' => ''], 'k'));
        self::assertSame([], StoredValues::array(['k' => []], 'k'));
        self::assertTrue(StoredValues::isTrue(['k' => true], 'k'));
        self::assertFalse(StoredValues::isTrue(['k' => false], 'k'));
        self::assertNull(StoredValues::optionalArray([], 'k'));
        self::assertNull(StoredValues::optionalArray(['k' => null], 'k'));
        self::assertSame(['a'], StoredValues::optionalArray(['k' => ['a']], 'k'));
        self::assertNull(StoredValues::restoredInstant(null));
        self::assertNull(StoredValues::instant(null));
        self::assertSame('2026-11-01T10:00:00.000001Z', StoredValues::restoredInstant('2026-11-01T10:00:00.000001Z')?->format(StoredValues::INSTANT_FORMAT));

        $refused = 0;

        $reads = [
            static fn (): string => StoredValues::string(['k' => 1], 'k'),
            static fn (): string => StoredValues::string([], 'k'),
            static fn (): ?string => StoredValues::optionalString(['k' => 1], 'k'),
            static fn (): array => StoredValues::array(['k' => 'a'], 'k'),
            static fn (): bool => StoredValues::isTrue(['k' => 1], 'k'),
            static fn (): bool => StoredValues::isTrue([], 'k'),
            static fn (): ?array => StoredValues::optionalArray(['k' => 'a'], 'k'),
            static fn (): ?CarbonImmutable => StoredValues::restoredInstant(1),
            static fn (): ?CarbonImmutable => StoredValues::restoredInstant('2026-11-01T10:00:00Z'),
            static fn (): mixed => StoredValues::restoring($throwing(new \ValueError('x'))),
            static fn (): mixed => StoredValues::restoring($throwing(new \TypeError('x'))),
            static fn (): mixed => StoredValues::restoring($throwing(new \InvalidArgumentException('x'))),
        ];

        foreach ($reads as $read) {
            try {
                $read();
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('A stored verified result is not one the package wrote.', $exception->getMessage());
                $refused++;
            }
        }

        self::assertSame(12, $refused);
        self::assertSame('kept', StoredValues::restoring(static fn (): string => 'kept'));

        $this->expectExceptionObject(new \RuntimeException('other'));

        StoredValues::restoring($throwing(new \RuntimeException('other')));
    }
}
