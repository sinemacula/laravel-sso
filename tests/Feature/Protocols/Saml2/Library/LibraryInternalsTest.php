<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\TestCase;

/**
 * Tests of the SAML adapter's own parsing parts: schemas, the entity loader and
 * refusals.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HardenedParser::class)]
#[CoversClass(MessageKind::class)]
#[CoversClass(ReadFailure::class)]
final class LibraryInternalsTest extends TestCase
{
    /**
     * Each kind of document is validated against its own schema, by an absolute
     * path inside the library.
     *
     * @return void
     */
    public function testEachKindHasItsSchemaByAbsolutePath(): void
    {
        self::assertSame(
            ['saml-schema-protocol-2.0.xsd', 'saml-schema-assertion-2.0.xsd', 'saml-schema-metadata-2.0.xsd'],
            array_map(static fn (MessageKind $kind): string => $kind->schema(), MessageKind::cases()),
        );

        foreach (MessageKind::cases() as $kind) {
            $path = HardenedParser::schemaPath($kind);

            self::assertStringStartsWith('/', $path);
            self::assertStringEndsWith('/simplesamlphp/saml2/resources/schemas/' . $kind->schema(), $path);
            self::assertFileExists($path);
        }
    }

    /**
     * The entity loader answers only a schema file in the library's directory,
     * by its real path.
     *
     * @return void
     */
    public function testTheEntityLoaderHoldsValidationToTheLibrarysSchemas(): void
    {
        $protocol  = HardenedParser::schemaPath(MessageKind::PROTOCOL);
        $directory = dirname($protocol);

        self::assertSame($protocol, HardenedParser::localSchema($protocol));
        self::assertSame($protocol, HardenedParser::localSchema($directory . '/../schemas/saml-schema-protocol-2.0.xsd'));
        self::assertNull(HardenedParser::localSchema('http://www.w3.org/2001/XMLSchema.dtd'));
        self::assertNull(HardenedParser::localSchema(__FILE__));
        self::assertNull(HardenedParser::localSchema($directory));
        self::assertNull(HardenedParser::localSchema($directory . '/../../composer.json'));
        self::assertNull(HardenedParser::localSchema($directory . 'x/saml-schema-protocol-2.0.xsd'));
        self::assertNull(HardenedParser::localSchema(null));
    }

    /**
     * Schema validation loads every schema through the parser's own loader and
     * leaves no loader installed.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function testEveryValidationLoadsThroughTheParsersOwnLoader(): void
    {
        $asked = [];
        $xml   = (new FakeSamlIdentityProvider)->response('https://sp.example.test/saml', 'https://sp.example.test/saml/acs')->toXml();

        libxml_set_external_entity_loader(static function (?string $public, ?string $system) use (&$asked): ?string {
            $asked[] = $system;

            return $system;
        });

        try {
            $document = (new HardenedParser)->parse($xml, MessageKind::PROTOCOL, strlen($xml));
            $loader   = libxml_get_external_entity_loader();
        } finally {
            libxml_set_external_entity_loader(null);
        }

        self::assertSame('Response', $document->documentElement?->localName);
        self::assertSame([], $asked);
        self::assertNull($loader);
    }

    /**
     * A refusal carries its reason and rule, as its message, and nothing else.
     *
     * @return void
     */
    public function testARefusalNamesOnlyItsRule(): void
    {
        $failure = new ReadFailure(FailureReason::RESPONSE_INVALID, 'schema');

        self::assertSame([FailureReason::RESPONSE_INVALID, 'schema', 'schema', null], [$failure->reason, $failure->detail, $failure->getMessage(), $failure->getPrevious()]);
    }

    /**
     * The parser refuses a decoded value of nothing, and a document over the
     * cap before it parses it, with the reason it is given.
     *
     * @return void
     */
    public function testTheParserRefusesWithTheReasonGiven(): void
    {
        $parser = new HardenedParser;

        $calls = [
            static fn () => $parser->decode('====', 100, FailureReason::METADATA_INVALID),
            static fn () => $parser->load('<x/>', 3, FailureReason::METADATA_INVALID),
        ];

        foreach ($calls as $call) {
            try {
                $call();
                self::fail('The parser answered.');
            } catch (ReadFailure $failure) {
                self::assertSame(FailureReason::METADATA_INVALID, $failure->reason);
            }
        }

        self::assertSame('<x/>', $parser->decode(base64_encode('<x/>'), 8));
        self::assertSame('x', $parser->load('<x/>', 4)->documentElement?->localName);
    }
}
