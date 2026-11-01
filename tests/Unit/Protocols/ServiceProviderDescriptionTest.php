<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;

/**
 * Unit tests for the description of a connection's service provider side: a
 * document with its content type, or unavailable with a reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ServiceProviderDescription::class)]
final class ServiceProviderDescriptionTest extends TestCase
{
    /**
     * A described connection carries its document and content type.
     *
     * @return void
     */
    public function testADocumentCarriesItsContentTypeAndBody(): void
    {
        $description = ServiceProviderDescription::document('application/samlmetadata+xml', '<md:EntityDescriptor/>');

        self::assertTrue($description->isAvailable());
        self::assertSame('application/samlmetadata+xml', $description->contentType);
        self::assertSame('<md:EntityDescriptor/>', $description->body);
        self::assertNull($description->reason);
    }

    /**
     * An unavailable description carries its reason and no document.
     *
     * @return void
     */
    public function testAnUnavailableDescriptionCarriesItsReason(): void
    {
        $description = ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE);

        self::assertFalse($description->isAvailable());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $description->reason);
        self::assertNull($description->contentType);
        self::assertNull($description->body);
    }

    /**
     * A document needs a content type and a body.
     *
     * @return void
     */
    public function testADocumentNeedsAContentTypeAndABody(): void
    {
        foreach ([['', 'body'], ['application/json', '']] as [$type, $body]) {

            try {
                ServiceProviderDescription::document($type, $body);
                self::fail('An empty part was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A description has a content type and a body.', $exception->getMessage());
            }
        }
    }
}
