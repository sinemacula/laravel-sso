<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

/**
 * The metadata sources the package refreshes, by protocol (SSO-2.8): a SAML
 * connection's metadata (`SamlMetadataSource`) and an OIDC connection's
 * discovery document and JWKS (`OidcMetadataSource`). A protocol an application
 * registered has none, so its connections never refresh.
 *
 * It holds the sources, none of which keeps anything of one refresh for the
 * next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MetadataSources
{
    /** @var array<string, \SineMacula\Laravel\Sso\Metadata\MetadataSource> Each source, by its protocol. */
    private array $sources;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\SamlMetadataSource  $saml
     * @param  \SineMacula\Laravel\Sso\Metadata\OidcMetadataSource  $oidc
     */
    public function __construct(

        // A SAML connection's metadata
        SamlMetadataSource $saml,

        // An OIDC connection's discovery document and JWKS
        OidcMetadataSource $oidc,
    ) {
        $this->sources = [$saml->protocol() => $saml, $oidc->protocol() => $oidc];
    }

    /**
     * The source of the protocol, or `null` when it has none.
     *
     * @param  string  $protocol
     * @return ?\SineMacula\Laravel\Sso\Metadata\MetadataSource
     */
    public function for(string $protocol): ?MetadataSource
    {
        return $this->sources[$protocol] ?? null;
    }

    /**
     * The protocols that have a source, in the order the package names them.
     *
     * @return list<string>
     */
    public function protocols(): array
    {
        return array_keys($this->sources);
    }
}
