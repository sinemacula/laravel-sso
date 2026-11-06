<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Compat\MockContainer;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\LibraryContainer;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\TestCase;

/**
 * Tests of the SAML adapter's own parts (SSO-6.1, SSO-11.2): the library's
 * container, set once by the package, kept, a container set by anything else
 * refused, and refusing every service the package never uses; the schema of
 * each kind of document, by absolute path; the entity loader that holds schema
 * validation to the library's own files, installed for every validation and
 * removed after it; and a refusal that names only its rule.
 *
 * The library is named here only to observe its container; the package's code
 * names it only inside the adapter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LibraryContainer::class)]
#[CoversClass(HardenedParser::class)]
#[CoversClass(MessageKind::class)]
#[CoversClass(ReadFailure::class)]
final class LibraryInternalsTest extends TestCase
{
    /**
     * In a process where no container is set yet, the package sets its own,
     * once, and keeps it: ensuring it again, as every request of a long-running
     * process does, keeps the same instance.
     *
     * @return void
     */
    #[RunInSeparateProcess]
    public function testTheContainerIsSetOnceAndKept(): void
    {
        self::assertFalse((new \ReflectionProperty(ContainerSingleton::class, 'container'))->isInitialized());

        LibraryContainer::ensure();

        $set = ContainerSingleton::getInstance();

        LibraryContainer::ensure();
        LibraryContainer::ensure();

        self::assertInstanceOf(LibraryContainer::class, $set);
        self::assertSame($set, ContainerSingleton::getInstance());
    }

    /**
     * A container something else set is refused, naming the problem, and left
     * as it is; the package's own set before is kept.
     *
     * @return void
     */
    public function testAContainerSomethingElseSetIsRefused(): void
    {
        $foreign  = new MockContainer;
        $previous = self::setContainer($foreign);

        try {
            LibraryContainer::ensure();
            self::fail('A container something else set was used.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'The SAML library\'s process-wide container is already set to [' . MockContainer::class . '], not the package\'s own: '
                . 'the package runs SAML only through the container it sets itself.',
                $exception->getMessage(),
            );
            self::assertSame($foreign, ContainerSingleton::getInstance());
        } finally {
            ContainerSingleton::setContainer($previous);
        }

        $own = new LibraryContainer;

        self::setContainer($own);

        try {
            LibraryContainer::ensure();

            self::assertSame($own, ContainerSingleton::getInstance());
        } finally {
            ContainerSingleton::setContainer($previous);
        }
    }

    /**
     * A parse refuses to run through a container something else set.
     *
     * @return void
     */
    public function testAParseRefusesAContainerSomethingElseSet(): void
    {
        $previous = self::setContainer(new MockContainer);

        try {
            (new HardenedParser)->load('<x/>', 4);
            self::fail('A parse ran through a container something else set.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(\LogicException::class, $exception);
            self::assertStringContainsString('not the package\'s own', $exception->getMessage());
        } finally {
            ContainerSingleton::setContainer($previous);
        }
    }

    /**
     * The container discards logs and debug messages, and refuses every service
     * the package never uses.
     *
     * @return void
     */
    public function testTheContainerRefusesWhatThePackageNeverUses(): void
    {
        $container = new LibraryContainer;

        $container->debugMessage('<samlp:Response/>', 'in');
        $container->getLogger()->error('discarded');

        $refusals = [
            'blacklist'           => static fn () => $container->setBlacklistedAlgorithms([]),
            'redirects'           => static fn () => $container->getPOSTRedirectURL('https://example.com'),
            'temporary directory' => static fn () => $container->getTempDir(),
            'files'               => static fn () => $container->writeFile('a', 'b'),
            'clock'               => static fn () => $container->getClock(),
            'inflate size limit'  => static fn () => $container->getInflateSizeLimit(),
        ];

        foreach ($refusals as $service => $call) {
            try {
                $call();
                self::fail("The container answered its {$service}.");
            } catch (\LogicException $exception) {
                self::assertSame("The SAML adapter never asks the library for its {$service}.", $exception->getMessage());
            }
        }
    }

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
     * The entity loader answers a schema file in the library's directory by its
     * real path, and nothing else: no URL, no file elsewhere, no path that
     * escapes the directory, and nothing for no path.
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
     * Schema validation loads every schema through the parser's own entity
     * loader: a loader the application set beforehand is never asked for the
     * schemas a valid response needs (though validation loads several), and
     * once validation ends no loader is left installed.
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
     * Set the library's container, and answer the package's own that was set
     * before, set first when none was, to restore afterwards.
     *
     * @param  \SimpleSAML\SAML2\Compat\AbstractContainer  $container
     * @return \SimpleSAML\SAML2\Compat\AbstractContainer
     */
    private static function setContainer(AbstractContainer $container): AbstractContainer
    {
        LibraryContainer::ensure();

        $previous = ContainerSingleton::getInstance();

        ContainerSingleton::setContainer($container);

        return $previous;
    }
}
