<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

use Carbon\CarbonImmutable;
use Random\RandomException;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;

/**
 * One SAML `Response` from the fake identity provider, valid and unsolicited by
 * default; every change returns a new response. In `with()`, `false` or `null`
 * leaves a part out, and `unknown_conditions` adds conditions that fail schema
 * validation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type SubjectDefaults array{
 *     confirmations: list<array{
 *         method: string, data: bool, recipient: ?string, not_before: ?\Carbon\CarbonImmutable,
 *         not_on_or_after: ?\Carbon\CarbonImmutable, in_response_to: ?string
 *     }>,
 *     authn_statements: list<array{
 *         instant: \Carbon\CarbonImmutable, session_index: ?string, session_not_on_or_after: ?\Carbon\CarbonImmutable, class: ?string
 *     }>
 * }
 * @phpstan-type ResponseOptions array{
 *     response_id: string, assertion_id: string, issue_instant: \Carbon\CarbonImmutable, assertion_issue_instant: \Carbon\CarbonImmutable,
 *     issuer: ?string, assertion_issuer: string, destination: ?string, in_response_to: ?string,
 *     status: string, sub_status: ?string, status_message: ?string, assertion: bool,
 *     subject: bool, name_id: ?string, name_id_format: ?string, name_qualifier: ?string, sp_name_qualifier: ?string,
 *     confirmations: list<array{
 *         method: string, data: bool, recipient: ?string, not_before: ?\Carbon\CarbonImmutable,
 *         not_on_or_after: ?\Carbon\CarbonImmutable, in_response_to: ?string
 *     }>,
 *     conditions: bool, not_before: ?\Carbon\CarbonImmutable, not_on_or_after: ?\Carbon\CarbonImmutable, audiences: list<list<string>>,
 *     one_time_use: int, proxy_restriction: int, unknown_conditions: int,
 *     authn_statements: list<array{
 *         instant: \Carbon\CarbonImmutable, session_index: ?string, session_not_on_or_after: ?\Carbon\CarbonImmutable, class: ?string
 *     }>,
 *     attributes: array<string, list<string>>, attribute_name_format: ?string, advice: bool,
 *     sign_response: bool, sign_assertion: bool, algorithm: string, digest: string, comments: bool, uri: ?string,
 *     encrypt: ?array{certificate: string, key_transport: string, data: string}, wrap: ?string, evil_name_id: string
 * }
 */
final readonly class FakeSamlResponse
{
    /** @var string The persistent NameID format. */
    public const string PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /** @var string The status code of a successful response. */
    public const string SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    /** @var string The bearer confirmation method. */
    public const string BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

    /** @var string The password-protected-transport authentication context class. */
    public const string PASSWORD_PROTECTED_TRANSPORT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\XmlSigner  $signer
     * @param  ResponseOptions  $options
     */
    public function __construct(

        /** Signs the response and the assertion. */
        private XmlSigner $signer,

        /** What the response holds. */
        private array $options,
    ) {}

    /**
     * The options of a valid response at the instant, with a signed assertion
     * and an unsigned envelope.
     *
     * @param  string  $idpEntityId
     * @param  string  $spEntityId
     * @param  string  $acsUrl
     * @param  \Carbon\CarbonImmutable  $now
     * @return ResponseOptions
     *
     * @throws \LogicException
     */
    public static function defaults(string $idpEntityId, string $spEntityId, string $acsUrl, CarbonImmutable $now): array
    {
        try {
            $suffix = bin2hex(random_bytes(8));
        } catch (RandomException $exception) {
            throw new \LogicException('The fake identity provider has no source of randomness.', 0, $exception);
        }

        return [
            'response_id'             => '_response-' . $suffix,
            'assertion_id'            => '_assertion-' . $suffix,
            'issue_instant'           => $now,
            'assertion_issue_instant' => $now,
            'issuer'                  => $idpEntityId,
            'assertion_issuer'        => $idpEntityId,
            'destination'             => $acsUrl,
            'in_response_to'          => null,
            'status'                  => self::SUCCESS,
            'sub_status'              => null,
            'status_message'          => null,
            'assertion'               => true,
            'subject'                 => true,
            'name_id'                 => 'alice',
            'name_id_format'          => self::PERSISTENT,
            'name_qualifier'          => null,
            'sp_name_qualifier'       => null,
            ...self::subjectDefaults($acsUrl, $now, $suffix),
            'conditions'            => true,
            'not_before'            => $now->subMinute(),
            'not_on_or_after'       => $now->addMinutes(5),
            'audiences'             => [[$spEntityId]],
            'one_time_use'          => 0,
            'proxy_restriction'     => 0,
            'unknown_conditions'    => 0,
            'attributes'            => ['email' => ['alice@example.test']],
            'attribute_name_format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
            'advice'                => false,
            'sign_response'         => false,
            'sign_assertion'        => true,
            'algorithm'             => 'rsa-sha256',
            'digest'                => 'sha256',
            'comments'              => false,
            'uri'                   => null,
            'encrypt'               => null,
            'wrap'                  => null,
            'evil_name_id'          => 'mallory',
        ];
    }

    /**
     * A response with the options given changed and every other kept.
     *
     * @param  array<string, mixed>  $changes
     * @return self
     */
    public function with(array $changes): self
    {
        /** @var ResponseOptions $options */
        $options = [...$this->options, ...$changes];

        return new self($this->signer, $options);
    }

    /**
     * A response whose own and every confirmation's `InResponseTo` is the id;
     * `null` clears them.
     *
     * @param  ?string  $requestId
     * @return self
     */
    public function inResponseTo(?string $requestId): self
    {
        $confirmations = $this->options['confirmations'];

        foreach ($confirmations as $index => $confirmation) {
            $confirmations[$index]['in_response_to'] = $requestId;
        }

        return $this->with(['in_response_to' => $requestId, 'confirmations' => $confirmations]);
    }

    /**
     * A response with the response and assertion signatures as given.
     *
     * @param  bool  $response
     * @param  bool  $assertion
     * @return self
     */
    public function signed(bool $response = false, bool $assertion = true): self
    {
        return $this->with(['sign_response' => $response, 'sign_assertion' => $assertion]);
    }

    /**
     * A response signed by another key, carrying its certificate.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\XmlSigner  $signer
     * @return self
     */
    public function signedBy(XmlSigner $signer): self
    {
        return new self($signer, $this->options);
    }

    /**
     * A response whose assertion is encrypted for the certificate.
     *
     * @param  string  $certificate
     * @param  string  $keyTransport
     * @param  string  $data
     * @return self
     */
    public function encryptedFor(string $certificate, string $keyTransport = 'rsa-oaep-mgf1p', string $data = 'aes128-gcm'): self
    {
        return $this->with(['encrypt' => ['certificate' => $certificate, 'key_transport' => $keyTransport, 'data' => $data]]);
    }

    /**
     * A response attacked with the wrapping variant.
     *
     * @param  string  $variant
     * @return self
     */
    public function wrapped(string $variant): self
    {
        return $this->with(['wrap' => $variant]);
    }

    /**
     * The value of an option.
     *
     * @param  string  $name
     * @return mixed
     */
    public function option(string $name): mixed
    {
        return $this->options[$name] ?? null;
    }

    /**
     * The response's XML.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function toXml(): string
    {
        try {
            return $this->written();
        } catch (\DOMException $exception) {
            throw new \LogicException('The fake identity provider could not write its response.', 0, $exception);
        }
    }

    /**
     * The response base64 encoded for the HTTP-POST binding, never deflated.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function encoded(): string
    {
        return base64_encode($this->toXml());
    }

    /**
     * The form fields the browser posts to the assertion consumer service.
     *
     * @param  ?string  $relayState
     * @return array<string, string>
     *
     * @throws \LogicException
     */
    public function post(?string $relayState = null): array
    {
        return array_filter(['SAMLResponse' => $this->encoded(), 'RelayState' => $relayState], static fn (?string $value): bool => $value !== null);
    }

    /**
     * What arrives at the ACS when the browser posts the response.
     *
     * @param  ?string  $relayState
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     *
     * @throws \LogicException
     */
    public function completionRequest(?string $relayState = null): CompletionRequest
    {
        return new CompletionRequest('POST', '', $this->post($relayState));
    }

    /**
     * The XML `toXml()` returns, letting a DOM failure through.
     *
     * @return string
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private function written(): string
    {
        $wrap = $this->options['wrap'];

        if ($wrap !== null) {
            return $this->wrappedXml($wrap);
        }

        $document = self::load((new ResponseWriter)->response($this->options, $this->assertionPart()));

        if ($this->options['sign_response']) {
            $this->signer->sign(self::root($document), $this->signatureOptions());
        }

        return (string) $document->saveXML($document->documentElement);
    }

    /**
     * The default bearer confirmation and authentication statement.
     *
     * @param  string  $acsUrl
     * @param  \Carbon\CarbonImmutable  $now
     * @param  string  $suffix
     * @return SubjectDefaults
     */
    private static function subjectDefaults(string $acsUrl, CarbonImmutable $now, string $suffix): array
    {
        $deadline = $now->addHours(8);

        return [
            'confirmations' => [
                ['method' => self::BEARER, 'data' => true, 'recipient' => $acsUrl, 'not_before' => null, 'not_on_or_after' => $now->addMinutes(5), 'in_response_to' => null],
            ],
            'authn_statements' => [
                ['instant' => $now->subMinute(), 'session_index' => '_session-' . $suffix, 'session_not_on_or_after' => $deadline, 'class' => self::PASSWORD_PROTECTED_TRANSPORT],
            ],
        ];
    }

    /**
     * The assertion, signed and encrypted as asked, or nothing when left out.
     *
     * @return string
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private function assertionPart(): string
    {
        if (!$this->options['assertion']) {
            return '';
        }

        $assertion = (new ResponseWriter)->assertion($this->options);

        if ($this->options['sign_assertion']) {
            $document = self::load($assertion);

            $this->signer->sign(self::root($document), $this->signatureOptions());

            $assertion = (string) $document->saveXML($document->documentElement);
        }

        $encrypt = $this->options['encrypt'];

        return $encrypt === null ? $assertion : (new AssertionEncryptor)->encrypt($assertion, $encrypt['certificate'], $encrypt['key_transport'], $encrypt['data']);
    }

    /**
     * The response wrapped with the variant; XSW1 and XSW2 sign the response,
     * the others the assertion.
     *
     * @param  string  $variant
     * @return string
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private function wrappedXml(string $variant): string
    {
        $response = in_array($variant, SignatureWrapping::RESPONSE_VARIANTS, true);
        $signed   = $this->with(['wrap' => null, 'encrypt' => null])->signed($response, !$response);
        $evil     = $this->with(['name_id' => $this->options['evil_name_id'], 'wrap' => null, 'encrypt' => null, 'sign_response' => false, 'sign_assertion' => false]);

        $evilXml = match (true) {
            $response                            => $evil->with(['response_id' => '_evil-response'])->toXml(),
            str_starts_with($variant, 'same_id') => (new ResponseWriter)->assertion($evil->options),
            default                              => (new ResponseWriter)->assertion($evil->with(['assertion_id' => '_evil-assertion'])->options),
        };

        $document = (new SignatureWrapping)->apply($variant, self::load($signed->toXml()), $evilXml);

        return (string) $document->saveXML($document->documentElement);
    }

    /**
     * The signer's options for the response's signatures.
     *
     * @return array{algorithm: string, digest: string, comments: bool, uri?: string}
     */
    private function signatureOptions(): array
    {
        $options = ['algorithm' => $this->options['algorithm'], 'digest' => $this->options['digest'], 'comments' => $this->options['comments']];

        return $this->options['uri'] === null ? $options : [...$options, 'uri' => $this->options['uri']];
    }

    /**
     * The XML parsed.
     *
     * @param  string  $xml
     * @return \DOMDocument
     *
     * @throws \LogicException
     */
    private static function load(string $xml): \DOMDocument
    {
        $document = new \DOMDocument;

        if (!$document->loadXML($xml, LIBXML_NONET)) {
            throw new \LogicException('The fake identity provider wrote XML it cannot parse.');
        }

        return $document;
    }

    /**
     * The document's root.
     *
     * @param  \DOMDocument  $document
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function root(\DOMDocument $document): \DOMElement
    {
        return $document->documentElement ?? throw new \LogicException('A written document has a root.');
    }
}
