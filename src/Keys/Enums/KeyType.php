<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys\Enums;

/**
 * The kind of a key pair or a certificate's public key (SSO-2.6, SSO-2.7). The
 * package generates RSA keys of `sso.keys.rsa_bits` (3072 by default) and
 * elliptic curve keys on P-256, with OpenSSL; a trusted certificate may hold an
 * RSA key of at least 2048 bits or an elliptic curve key on P-256, P-384 or
 * P-521.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyType: string
{
    // RSA
    case RSA = 'rsa';

    // Elliptic curve
    case EC = 'ec';
}
