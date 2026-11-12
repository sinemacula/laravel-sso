<?php

declare(strict_types = 1);

/*
 * The constant-time comparisons of `docs/guides/secrets.md`.
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
