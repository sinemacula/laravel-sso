<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;

/**
 * The settings an import of SAML metadata proposes, trusted only once saved and
 * each certificate trusted through `Keys\KeyService::trustCertificate()`.
 *
 * Its values are untrusted, so a dump shows names and counts alone and it
 * refuses to be serialised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-import-type Certificate from \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
 *
 * @phpstan-type Proposal array{
 *     settings: array{idp_entity_id: string, sso_url: string, sso_binding: string},
 *     signing_certificates: list<array{certificate: string, fingerprint: string}>,
 *     encryption_certificates: list<array{certificate: string, fingerprint: string}>,
 *     name_id_formats: list<string>, valid_until: ?\Carbon\CarbonImmutable,
 *     fetched_at: ?\Carbon\CarbonImmutable
 * }
 */
final readonly class ProposedSettings implements \JsonSerializable
{
    /** @var \SensitiveParameterValue What the metadata proposes, by name. */
    private \SensitiveParameterValue $values;

    /**
     * Constructor.
     *
     * @param  Proposal  $values
     */
    private function __construct(
        // What the metadata proposes, by name; held wrapped
        #[\SensitiveParameter]
        array $values,
    ) {
        $this->values = new \SensitiveParameterValue($values);
    }

    /**
     * What a dump shows: the setting names and how many certificates and
     * formats, never a value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'settings'                => array_keys($this->settings()),
            'signing_certificates'    => count($this->signingCertificates()),
            'encryption_certificates' => count($this->encryptionCertificates()),
            'name_id_formats'         => count($this->nameIdFormats()),
            'valid_until'             => $this->validUntil() === null ? null : '[redacted]',
        ];
    }

    /**
     * Refuse to be serialised: what the metadata proposes lives only for the
     * administrator's review.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('Proposed settings cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('Proposed settings cannot be unserialised.');
    }

    /**
     * What the read metadata proposes, with when it was validated if fetched.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  ?\Carbon\CarbonImmutable  $fetchedAt
     * @return self
     *
     * @throws \LogicException
     */
    public static function of(IdpMetadata $metadata, ?CarbonImmutable $fetchedAt = null): self
    {
        return new self([
            'settings' => [
                'idp_entity_id' => $metadata->entityId(),
                'sso_url'       => $metadata->ssoUrl(),
                'sso_binding'   => $metadata->ssoBinding(),
            ],
            'signing_certificates'    => $metadata->signingCertificates(),
            'encryption_certificates' => $metadata->encryptionCertificates(),
            'name_id_formats'         => $metadata->nameIdFormats(),
            'valid_until'             => $metadata->validUntil(),
            'fetched_at'              => $fetchedAt,
        ]);
    }

    /**
     * The settings proposed: `idp_entity_id`, `sso_url` and `sso_binding`.
     *
     * @return array{idp_entity_id: string, sso_url: string, sso_binding: string}
     */
    public function settings(): array
    {
        return $this->all()['settings'];
    }

    /**
     * The signing certificates proposed, each with the fingerprint an
     * administrator checks out of band.
     *
     * @return list<Certificate>
     */
    public function signingCertificates(): array
    {
        return $this->all()['signing_certificates'];
    }

    /**
     * The encryption certificates the metadata names, each with its
     * fingerprint.
     *
     * @return list<Certificate>
     */
    public function encryptionCertificates(): array
    {
        return $this->all()['encryption_certificates'];
    }

    /**
     * The NameID formats the provider offers; the import never proposes one.
     *
     * @return list<string>
     */
    public function nameIdFormats(): array
    {
        return $this->all()['name_id_formats'];
    }

    /**
     * The earliest `validUntil` of the metadata, in UTC, or `null`.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function validUntil(): ?CarbonImmutable
    {
        return $this->all()['valid_until'];
    }

    /**
     * The fetch the metadata came from, or `null` for metadata given as XML.
     *
     * @return ?\SineMacula\Laravel\Sso\Metadata\ValidatedFetch
     */
    public function fetch(): ?ValidatedFetch
    {
        $fetchedAt = $this->all()['fetched_at'];

        return $fetchedAt === null ? null : new ValidatedFetch($fetchedAt, $this->validUntil());
    }

    /**
     * What `json_encode()` writes: what a dump shows.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * Everything proposed, by name.
     *
     * @return Proposal
     */
    private function all(): array
    {
        /** @var Proposal */
        return $this->values->getValue();
    }
}
