<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Saml;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Testing\Saml\FakeServiceProvider;
use SineMacula\Laravel\Sso\Testing\Saml\XmlDocument;

/**
 * Unit tests for the service provider the fake identity provider reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeServiceProvider::class)]
#[CoversClass(XmlDocument::class)]
final class FakeServiceProviderTest extends TestCase
{
    /** @var string The metadata, with its services in place of `{services}`. */
    private const string METADATA = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/metadata">'
        . '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{services}</md:SPSSODescriptor></md:EntityDescriptor>';

    /** @var string The HTTP-POST binding. */
    private const string POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    /** @var string The HTTP-Artifact binding. */
    private const string ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';

    /**
     * The entity id and the first HTTP-POST assertion consumer service, passing
     * over one of another binding.
     *
     * @return void
     */
    public function testReadsTheEntityAndItsPostService(): void
    {
        $services = [
            self::service(self::ARTIFACT, 'https://sp.example.test/artifact'),
            self::service(self::POST, 'https://sp.example.test/acs'),
            self::service(self::POST, 'https://sp.example.test/second'),
        ];

        $sp = FakeServiceProvider::fromMetadata(self::metadata(implode('', $services)));

        self::assertSame(['https://sp.example.test/metadata', 'https://sp.example.test/acs'], [$sp->entityId, $sp->assertionConsumerService]);
    }

    /**
     * Rows of `[metadata, message]`: what cannot be read, and why.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideUnreadable(): iterable
    {
        $post     = self::service(self::POST, 'https://sp.example.test/acs');
        $artifact = self::service(self::ARTIFACT, 'https://sp.example.test/artifact');

        yield 'not XML' => ['', 'The service provider metadata is not an XML document without a document type.'];
        yield 'another element' => ['<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>', 'The service provider metadata is not an EntityDescriptor.'];
        yield 'another namespace' => ['<EntityDescriptor entityID="https://sp.example.test/metadata"/>', 'The service provider metadata is not an EntityDescriptor.'];
        yield 'no entity id' => [str_replace(' entityID="https://sp.example.test/metadata"', '', self::metadata($post)), 'The EntityDescriptor has no entityID.'];
        yield 'no HTTP-POST service' => [self::metadata($artifact), 'The service provider metadata names no HTTP-POST assertion consumer service.'];
        yield 'a service without a location' => [self::metadata('<md:AssertionConsumerService Binding="' . self::POST . '"/>'), 'The AssertionConsumerService has no Location.'];
    }

    /**
     * Each refused with a `LogicException` saying why.
     *
     * @param  string  $metadata
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnreadable')]
    public function testRefusesWhatItCannotRead(string $metadata, string $message): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage($message);

        FakeServiceProvider::fromMetadata($metadata);
    }

    /**
     * The metadata holding the services given.
     *
     * @param  string  $services
     * @return string
     */
    private static function metadata(string $services): string
    {
        return str_replace('{services}', $services, self::METADATA);
    }

    /**
     * An assertion consumer service of the binding at the location.
     *
     * @param  string  $binding
     * @param  string  $location
     * @return string
     */
    private static function service(string $binding, string $location): string
    {
        return sprintf('<md:AssertionConsumerService Binding="%s" Location="%s" index="0"/>', $binding, $location);
    }
}
