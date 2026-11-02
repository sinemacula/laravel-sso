<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * An identity provider's metadata as the SAML adapter read it for one pinned
 * entity (SSO-2.8, SSO-6.11), or why it was refused.
 *
 * Read metadata holds the entity id; the single sign-on service chosen, its URL
 * and its binding (`http_redirect` or `http_post`, as the connection's
 * `sso_binding` names them); the RSA signing certificates and the encryption
 * certificates, each as its canonical PEM and lower-case hex SHA-256
 * fingerprint, once per fingerprint, in document order; the NameID formats
 * offered; and the earliest `validUntil` of the entity and every descriptor
 * enclosing it, or `null` for undated metadata.
 *
 * What the provider published lives in one `\SensitiveParameterValue`, so a
 * dump, an array cast and `json_encode()` show `[redacted]`, and the value
 * refuses to be serialised or unserialised. Refused metadata holds nothing but
 * the reason and the rule's name in the package's own words (`schema`,
 * `entity_location`, `signature`, say); asking it for a value is the caller's
 * mistake, a `LogicException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type Certificate array{certificate: string, fingerprint: string}
 * @phpstan-type MetadataValues array{
 *     entity_id: string, sso_url: string, sso_binding: string,
 *     signing_certificates: list<array{certificate: string, fingerprint: string}>,
 *     encryption_certificates: list<array{certificate: string, fingerprint: string}>,
 *     name_id_formats: list<string>, valid_until: ?\Carbon\CarbonImmutable
 * }
 */
final readonly class IdpMetadata implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?string  $detail
     * @param  array<string, mixed>  $values
     */
    private function __construct(

        /** Why the metadata was refused, for refused metadata. */
        public ?FailureReason $reason,

        /** Which rule refused it, in the package's own words, for refused metadata. */
        public ?string $detail,

        // What the provider published, by name; held wrapped
        #[\SensitiveParameter]
        array $values,
    ) {
        $this->hold($values);
    }

    /**
     * The metadata was read, and holds the values.
     *
     * @param  MetadataValues  $values
     * @return self
     */
    public static function read(#[\SensitiveParameter] array $values): self
    {
        return new self(null, null, $values);
    }

    /**
     * The metadata was refused, for the reason, by the rule named.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return self
     */
    public static function refused(FailureReason $reason, string $detail): self
    {
        return new self($reason, $detail, []);
    }

    /**
     * Whether the metadata was read.
     *
     * @return bool
     */
    public function isRead(): bool
    {
        return $this->reason === null;
    }

    /**
     * The entity id, exactly as the metadata carries it.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function entityId(): string
    {
        /** @var string */
        return $this->value('entity_id');
    }

    /**
     * The URL of the single sign-on service chosen.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function ssoUrl(): string
    {
        /** @var string */
        return $this->value('sso_url');
    }

    /**
     * The binding of the single sign-on service chosen: `http_redirect` or
     * `http_post`.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function ssoBinding(): string
    {
        /** @var string */
        return $this->value('sso_binding');
    }

    /**
     * The RSA signing certificates, each with its fingerprint, once each.
     *
     * @return list<Certificate>
     *
     * @throws \LogicException
     */
    public function signingCertificates(): array
    {
        /** @var list<Certificate> */
        return $this->value('signing_certificates');
    }

    /**
     * The encryption certificates, each with its fingerprint, once each.
     *
     * @return list<Certificate>
     *
     * @throws \LogicException
     */
    public function encryptionCertificates(): array
    {
        /** @var list<Certificate> */
        return $this->value('encryption_certificates');
    }

    /**
     * The NameID formats offered, once each, in document order.
     *
     * @return list<string>
     *
     * @throws \LogicException
     */
    public function nameIdFormats(): array
    {
        /** @var list<string> */
        return $this->value('name_id_formats');
    }

    /**
     * The earliest `validUntil` of the entity and its enclosing descriptors, in
     * UTC, or `null` for undated metadata.
     *
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \LogicException
     */
    public function validUntil(): ?CarbonImmutable
    {
        /** @var ?\Carbon\CarbonImmutable */
        return $this->value('valid_until');
    }

    /**
     * The value held under the name, which only read metadata has.
     *
     * @param  string  $name
     * @return mixed
     *
     * @throws \LogicException
     */
    private function value(string $name): mixed
    {
        if (!$this->isRead()) {
            throw new \LogicException('Refused metadata holds no value.');
        }

        return $this->held($name);
    }
}
