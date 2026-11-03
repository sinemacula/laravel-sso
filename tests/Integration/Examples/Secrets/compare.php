<?php

declare(strict_types = 1);

/*
 * The comparisons of `docs/guides/secrets.md` (SSO-11.9, SSO-12.5), as the
 * application's own code makes them, given a known secret and one given to it,
 * the stored SHA-256 and SHA-512 digests of a value and the value presented:
 * each is compared in constant time, and whether each matched is answered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\Secrets;

/**
 * @var array{
 *     known: string,
 *     given: string,
 *     storedSha256Hex: string,
 *     storedSha512Hex: string,
 *     presented: string
 * } $input
 */
$known           = $input['known'];
$given           = $input['given'];
$storedSha256Hex = $input['storedSha256Hex'];
$storedSha512Hex = $input['storedSha512Hex'];
$presented       = $input['presented'];

// @snippet-start constant-time
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

$secretMatches = ConstantTime::equals($known, $given);
$sha256Matches = ConstantTime::matchesDigest($storedSha256Hex, $presented);
$sha512Matches = ConstantTime::matchesDigest($storedSha512Hex, $presented, 'sha512');
// @snippet-end constant-time
return [$secretMatches, $sha256Matches, $sha512Matches];
