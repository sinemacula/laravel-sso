<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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

    /**
     * Rows of `[xml]`: a document repeating an identifier, through the same or
     * another identity attribute.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRepeatedIds(): iterable
    {
        yield 'ID twice' => ['<x ID="a"><y ID="a"/></x>'];
        yield 'ID and Id' => ['<x ID="a"><y Id="a"/></x>'];
        yield 'ID and id' => ['<x ID="a"><y id="a"/></x>'];
        yield 'ID and xml:id' => ['<x ID="a"><y xml:id="a"/></x>'];
    }

    /**
     * Loading for later validation checks no schema but still refuses an
     * identifier repeated, with the reason given.
     *
     * @param  string  $xml
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    #[DataProvider('provideRepeatedIds')]
    public function testLoadingUniqueSkipsTheSchemaButRefusesARepeatedId(string $xml): void
    {
        $parser = new HardenedParser;

        self::assertSame('x', $parser->loadUnique('<x ID="a"><y ID="b"/></x>', 100)->documentElement?->localName);

        try {
            $parser->loadUnique($xml, 100, FailureReason::METADATA_INVALID);
            self::fail('A repeated ID was loaded.');
        } catch (ReadFailure $failure) {
            self::assertSame([FailureReason::METADATA_INVALID, 'duplicate_id'], [$failure->reason, $failure->detail]);
        }
    }

    /**
     * An element is validated with the namespaces in scope where it sits, so a
     * prefix only an attribute value names still resolves.
     *
     * @return void
     *
     * @throws \DOMException
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function testAnElementIsValidatedWithItsInScopeNamespaces(): void
    {
        $parser = new HardenedParser;
        $entity = self::entity($parser, 'xs:string');
        $copy   = new \DOMDocument;

        $copy->appendChild($copy->importNode($entity, true));

        $parser->validateElement($entity, MessageKind::METADATA);

        $this->expectExceptionObject(new ReadFailure(FailureReason::METADATA_INVALID, 'schema'));

        $parser->parse((string) $copy->saveXML(), MessageKind::METADATA, 10000, FailureReason::METADATA_INVALID);
    }

    /**
     * An element is refused when a prefix it names is bound nowhere, or when it
     * belongs to no document.
     *
     * @return void
     *
     * @throws \DOMException
     */
    public function testAnElementIsRefusedWhenItsNamespacesCannotBeResolved(): void
    {
        $parser = new HardenedParser;

        $elements = [
            'schema'    => self::entity($parser, 'zz:string'),
            'structure' => new \DOMElement('EntityDescriptor'),
        ];

        foreach ($elements as $detail => $element) {
            try {
                $parser->validateElement($element, MessageKind::METADATA, FailureReason::METADATA_INVALID);
                self::fail('An element that cannot be resolved was validated.');
            } catch (ReadFailure $failure) {
                self::assertSame([FailureReason::METADATA_INVALID, $detail], [$failure->reason, $failure->detail]);
            }
        }
    }

    /**
     * The entity of an aggregate that binds `xs` only on itself, its attribute
     * value typed as given.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser  $parser
     * @param  string  $type
     * @return \DOMElement
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function entity(HardenedParser $parser, string $type): \DOMElement
    {
        $xml = '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            . ' xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            . '<md:EntityDescriptor entityID="https://idp.example.test/saml">'
            . '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/saml/sso"/>'
            . '<saml:Attribute Name="role"><saml:AttributeValue xsi:type="' . $type . '">admin</saml:AttributeValue></saml:Attribute>'
            . '</md:IDPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>';

        $entity = $parser->loadUnique($xml, strlen($xml))->documentElement?->firstChild;

        self::assertInstanceOf(\DOMElement::class, $entity);

        return $entity;
    }
}
