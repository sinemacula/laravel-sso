<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure;
use Tests\TestCase;

/**
 * Tests of the hardened parser's validation of one element.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HardenedParser::class)]
final class HardenedParserTest extends TestCase
{
    /**
     * Rows of `[child, without, valid]`: a child after the identity provider's
     * descriptor, the names left out, and whether the entity is then valid.
     *
     * @return iterable<string, array{0: string, 1: list<string>, 2: bool}>
     */
    public static function provideChildrenLeftOut(): iterable
    {
        $role = '<md:RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">'
            . '<fed:PassiveRequestorEndpoint/></md:RoleDescriptor>';
        $foreign = '<fed:RoleDescriptor/>';

        yield from [
            'named'             => [$role, ['RoleDescriptor'], true],
            'not named'         => [$role, [], false],
            'another namespace' => [$foreign, ['RoleDescriptor'], false],
        ];
    }

    /**
     * Only the named children of the element's own namespace are left out of
     * its validation, and the element itself keeps them.
     *
     * @param  string  $child
     * @param  list<string>  $without
     * @param  bool  $valid
     * @return void
     *
     * @throws \DOMException
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    #[DataProvider('provideChildrenLeftOut')]
    public function testOnlyTheNamedChildrenOfItsOwnNamespaceAreLeftOut(string $child, array $without, bool $valid): void
    {
        $parser = new HardenedParser;
        $xml    = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            . ' xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" entityID="https://idp.example.test/saml">'
            . '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/saml/sso"/>'
            . '</md:IDPSSODescriptor>' . $child . '</md:EntityDescriptor>';
        $entity = $parser->loadUnique($xml, strlen($xml))->documentElement;

        self::assertInstanceOf(\DOMElement::class, $entity);

        try {
            $parser->validateElement($entity, MessageKind::METADATA, FailureReason::METADATA_INVALID, $without);
            $detail = null;
        } catch (ReadFailure $failure) {
            $detail = [$failure->reason, $failure->detail];
        }

        self::assertSame($valid ? null : [FailureReason::METADATA_INVALID, 'schema'], $detail);
        self::assertSame($xml, $entity->ownerDocument?->saveXML($entity));
    }
}
