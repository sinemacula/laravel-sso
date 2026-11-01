<?php

declare(strict_types = 1);

namespace Tests\Feature\Results;

use Carbon\CarbonImmutable;
use Monolog\Formatter\FormatterInterface;
use Monolog\Formatter\JsonFormatter;
use Monolog\Formatter\LineFormatter;
use Monolog\Formatter\NormalizerFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\StoredValues;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\CapturesLogs;
use Tests\TestCase;

/**
 * Feature tests for what the parts of a verified result show when they leave
 * the code that holds them by JSON (SSO-9.8, SSO-11.9): `json_encode()`, a
 * Monolog formatter's normaliser, which falls back to JSON for an object, and
 * the package's own `SanitizingLogger` never show the subject or a value the
 * provider asserted, while a verified result's storage form keeps every value
 * and restores exactly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifiedClaims::class)]
#[CoversClass(AuthenticationContext::class)]
#[CoversClass(LinkingEmail::class)]
#[CoversClass(StoredValues::class)]
final class ResultPartsLoggingTest extends TestCase
{
    use CapturesLogs;

    /** @var list<string> Every value the provider asserted in the parts below. */
    private const array PROVIDER_VALUES = [
        'the-subject-value',
        'the-mail-value',
        'the-name-value',
        'the-method-value',
        'the-class-value',
        'the-session-value',
        'the-email-value',
        'the-organization-value',
        '2031',
        '2032',
    ];

    /**
     * `json_encode()` of the claims, the context and the linking email shows
     * none of the provider's values.
     *
     * @return void
     */
    public function testJsonEncodingShowsNoProviderValue(): void
    {
        foreach (self::parts() as $name => $part) {

            $json = (string) json_encode($part);

            self::assertStringContainsString('[redacted]', $json, $name);
            self::assertNoProviderValue($json, $name);
        }
    }

    /**
     * Logged as context through Monolog, whose formatters normalise an object
     * by its JSON, the parts show none of the provider's values, whatever the
     * formatter.
     *
     * @return void
     */
    public function testMonologsNormaliserShowsNoProviderValue(): void
    {
        $formatters = ['line' => new LineFormatter, 'json' => new JsonFormatter, 'normalizer' => new NormalizerFormatter];

        foreach ($formatters as $name => $formatter) {

            $formatted = self::formattedBy($formatter);

            self::assertStringContainsString('[redacted]', $formatted, $name);
            self::assertStringContainsString('the-attribute-names', $formatted, $name);
            self::assertNoProviderValue($formatted, $name);
        }
    }

    /**
     * Logged as context through the package's own logger, the parts show none
     * of the provider's values.
     *
     * @return void
     */
    public function testTheSanitizingLoggerShowsNoProviderValue(): void
    {
        $handler = $this->captureLogs();

        app(SanitizingLogger::class)->info('Completed.', self::parts());

        $records = $handler->getRecords();

        self::assertCount(1, $records);
        self::assertSame('Completed.', $records[0]->message);
        $formatted = $records[0]->formatted;

        self::assertIsString($formatted);
        self::assertStringContainsString('Completed.', $formatted);
        self::assertNoProviderValue((string) json_encode($records[0]->context), 'context');
        self::assertNoProviderValue($formatted, 'formatted');
    }

    /**
     * A verified result built from the parts keeps every value in its storage
     * form, which `json_encode()` and `serialize()` write and which restores
     * exactly: the parts' redacted JSON never reaches it.
     *
     * @return void
     */
    public function testAVerifiedResultStillStoresEveryValue(): void
    {
        $context = self::context();
        $email   = self::email();
        $result  = new VerifiedResult(
            issuer: 'https://idp.example.com',
            subject: 'the-subject-value',
            nameIdFormat: null,
            connectionId: '01jbexampleconnection00000',
            tenantId: 'tenant-1',
            protocol: 'oidc',
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString(str_repeat('r', 32)),
            attributes: ['email' => 'the-mail-value@example.com'],
            emailDomainVerified: true,
            authenticationContext: $context,
            linkingEmail: $email,
        );

        $json = (string) json_encode($result);

        /** @var array<string, mixed> $stored */
        $stored = json_decode($json, true);

        self::assertSame((string) json_encode($result->toArray()), $json);
        self::assertSame($context->toArray(), $stored['authentication_context']);
        self::assertSame($email->toArray(), $stored['linking_email']);
        self::assertSame($result->toArray(), VerifiedResult::restore($stored)->toArray());

        $unserialized = unserialize(serialize($result));

        self::assertInstanceOf(VerifiedResult::class, $unserialized);
        self::assertSame($result->toArray(), $unserialized->toArray());
    }

    /**
     * Assert the text shows none of the provider's values.
     *
     * @param  string  $text
     * @param  string  $name
     * @return void
     */
    private static function assertNoProviderValue(string $text, string $name): void
    {
        foreach (self::PROVIDER_VALUES as $value) {
            self::assertStringNotContainsString($value, $text, "{$name} shows [{$value}].");
        }
    }

    /**
     * What the formatter writes of a record whose context holds the parts.
     *
     * @param  \Monolog\Formatter\FormatterInterface  $formatter
     * @return string
     */
    private static function formattedBy(FormatterInterface $formatter): string
    {
        $handler = new TestHandler;

        $handler->setFormatter($formatter);

        (new Logger('results', [$handler]))->info('Completed.', self::parts());

        $formatted = $handler->getRecords()[0]->formatted;

        return is_string($formatted) ? $formatted : (string) json_encode($formatted);
    }

    /**
     * Claims, an authentication context and a linking email with every part
     * set, each value distinct, by name.
     *
     * @return array<string, object>
     */
    private static function parts(): array
    {
        return [
            'claims' => new VerifiedClaims(
                'https://idp.example.com',
                'the-subject-value',
                null,
                ['the-attribute-names' => ['the-mail-value@example.com'], 'name' => 'the-name-value'],
                self::context(),
                self::email(),
            ),
            'context' => self::context(),
            'email'   => self::email(),
        ];
    }

    /**
     * An authentication context with every part set, each value distinct.
     *
     * @return \SineMacula\Laravel\Sso\Results\AuthenticationContext
     */
    private static function context(): AuthenticationContext
    {
        return new AuthenticationContext(
            CarbonImmutable::parse('2031-02-03T04:05:06Z'),
            ['the-method-value'],
            'the-class-value',
            'the-session-value',
            CarbonImmutable::parse('2032-03-04T05:06:07Z'),
        );
    }

    /**
     * A linking email with an organisation, each value distinct.
     *
     * @return \SineMacula\Laravel\Sso\Results\LinkingEmail
     */
    private static function email(): LinkingEmail
    {
        return new LinkingEmail('the-email-value@example.com', LinkingEmailSource::ID_TOKEN, 'the-organization-value');
    }
}
