<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys\Enums;

/**
 * The kind of a key pair or a certificate's public key.
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
