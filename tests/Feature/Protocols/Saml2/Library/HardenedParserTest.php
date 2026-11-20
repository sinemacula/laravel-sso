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
 * Tests of the hardened parser's re-rooting and validation of one element.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HardenedParser::class)]
final class HardenedParserTest extends TestCase
{
    /** @var string The exclusive canonicalisation namespace. */
    private const string NS_EC = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /** @var string The XML Schema instance namespace. */
    private const string NS_XSI = 'http://www.w3.org/2001/XMLSchema-instance';

    /**
     * A re-rooted element is the root of a document of its own, keeps each
     * nested declaration where it was, and declares what it inherits only where
     * a name, an `xsi:type` or an `InclusiveNamespaces` within it relies on it; a root
     * inherits nothing.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function testAReRootedElementKeepsTheDeclarationsItReliesOn(): void
    {
        $xml = '<p:Response xmlns:p="urn:p" xmlns:xs="urn:xs" xmlns="urn:d" xmlns:q="urn:a&amp;b" xmlns:u="urn:unused" xmlns:xsi="' . self::NS_XSI . '" xml:lang="en">'
            . '<Assertion ID="_a" xsi:type="xs:string"><!-- kept --><Signature xmlns="urn:ds"><SignedInfo>'
            . '<ec:InclusiveNamespaces xmlns:ec="' . self::NS_EC . '" PrefixList="q"/></SignedInfo></Signature>'
            . '<p:Used/><Value xmlns:y="urn:y" type="y:z"/><Plain xmlns=""/><Rebound xmlns:xs="urn:other" type="xs:t"/></Assertion>'
            . '<p:Typed xsi:type="Local"/></p:Response>';
        $root = (new HardenedParser)->load($xml, strlen($xml))->documentElement;

        self::assertInstanceOf(\DOMElement::class, $root?->firstChild);
        self::assertInstanceOf(\DOMElement::class, $root->lastChild);

        $copy = HardenedParser::reRooted($root->firstChild);

        // libxml before 2.13 keeps the URI escaped, so its form varies
        self::assertSame(1, preg_match('/ xmlns:q="[^"]*"/', $root->C14N(), $q));
        self::assertSame($copy, $copy->ownerDocument?->documentElement);
        self::assertNotSame($root->ownerDocument, $copy->ownerDocument);
        self::assertSame(
            '<Assertion xmlns="urn:d" xmlns:p="urn:p"' . $q[0] . ' xmlns:xs="urn:xs" xmlns:xsi="' . self::NS_XSI . '" ID="_a" xsi:type="xs:string">'
            . '<!-- kept --><Signature xmlns="urn:ds"><SignedInfo>'
            . '<ec:InclusiveNamespaces xmlns:ec="' . self::NS_EC . '" PrefixList="q"></ec:InclusiveNamespaces></SignedInfo></Signature>'
            . '<p:Used></p:Used><Value xmlns:y="urn:y" type="y:z"></Value><Plain xmlns=""></Plain><Rebound xmlns:xs="urn:other" type="xs:t"></Rebound></Assertion>',
            $copy->C14N(false, true),
        );
        self::assertSame($root->firstChild->C14N(true, false, null, ['q']), $copy->C14N(true, false, null, ['q']));
        self::assertSame('urn:d', HardenedParser::reRooted($root->lastChild)->lookupNamespaceURI(null));
        self::assertSame($root->C14N(true), HardenedParser::reRooted($root)->C14N(true));

        $quoted = (new HardenedParser)->load($xml = '<r xmlns:p=\'urn:a"b\'><a><p:b/></a></r>', strlen($xml))->documentElement?->firstChild;

        self::assertInstanceOf(\DOMElement::class, $quoted);
        self::assertSame('urn:a"b', HardenedParser::reRooted($quoted)->lookupNamespaceURI('p'));

        $referenced = (new HardenedParser)->load($xml = '<r xmlns:p="urn:a&amp;#38;&lt;&gt;&quot;&#x22;b"><a><p:b/></a></r>', strlen($xml))->documentElement?->firstChild;

        self::assertInstanceOf(\DOMElement::class, $referenced);
        self::assertSame($referenced->lookupNamespaceURI('p'), HardenedParser::reRooted($referenced)->lookupNamespaceURI('p'));
    }

    /**
     * Rows of `[xml, prefixes]`: an element whose namespaces are bound more
     * than once where it stands, and the prefixes its canonicalisation keeps.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideRepeatedBindings(): iterable
    {
        yield from [
            'an alias it keeps beside the default it declares' => [
                '<r xmlns:p="urn:p" xmlns:saml="urn:a" xmlns:q="urn:q"><Assertion xmlns="urn:a" ID="_a" Note="x&gt;y&quot;z">'
                    . '<Issuer/><p:Used/><q:Used/><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="saml"/></Assertion></r>',
                ['saml'],
            ],
            'its own prefix inherited beside a default' => ['<r xmlns:saml="urn:a" xmlns:p="urn:p"><saml:Assertion xmlns="urn:a"><saml:Issuer/></saml:Assertion></r>', []],
            'a default it keeps but does not use'       => [
                '<r xmlns="urn:d" xmlns:p="urn:p"><p:A><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="#default"/></p:A></r>',
                ['#default'],
            ],
            'an unused alias of a namespace it uses'    => ['<r xmlns:p="urn:x" xmlns:q="urn:x"><A xmlns="urn:a"><p:B/></A></r>', []],
            'a prefix list outside a canonicalisation'  => ['<r xmlns:q="urn:x"><A xmlns="urn:a"><p:Thing xmlns:p="urn:x" PrefixList="q"/></A></r>', []],
            'an unused prefix a descendant binds again' => ['<r xmlns:p="urn:unused"><A xmlns="urn:a"><p:B xmlns:p="urn:x"/></A></r>', []],
            'an inherited prefix it binds again'        => [
                '<r xmlns:q1="urn:q1" xmlns:p="urn:p" xmlns:q2="urn:q2"><Assertion xmlns:p="urn:other"><p:Used/><q1:Used/><q2:Used/>'
                    . '<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="p"/></Assertion></r>',
                ['p'],
            ],
        ];
    }

    /**
     * Copied again as the SAML library copies what it digests, a re-rooted
     * element canonicalises as it did in place.
     *
     * @param  string  $xml
     * @param  list<string>  $prefixes
     * @return void
     *
     * @throws \DOMException
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    #[DataProvider('provideRepeatedBindings')]
    public function testABindingSurvivesTheLibrarysCopy(string $xml, array $prefixes): void
    {
        $element = (new HardenedParser)->load($xml, strlen($xml))->documentElement?->firstChild;

        self::assertInstanceOf(\DOMElement::class, $element);

        $document = new \DOMDocument;

        $document->appendChild($document->importNode(HardenedParser::reRooted($element), true));

        self::assertSame($element->C14N(true, false, null, $prefixes), $document->documentElement?->C14N(true, false, null, $prefixes));
    }

    /**
     * An element outside any document is refused for the reason given.
     *
     * @return void
     *
     * @throws \DOMException
     */
    public function testAnElementOutsideADocumentIsRefused(): void
    {
        try {
            HardenedParser::reRooted(new \DOMElement('EntityDescriptor'), FailureReason::METADATA_INVALID);
            self::fail('An element outside a document was re-rooted.');
        } catch (ReadFailure $failure) {
            self::assertSame([FailureReason::METADATA_INVALID, 'structure'], [$failure->reason, $failure->detail]);
        }
    }

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
