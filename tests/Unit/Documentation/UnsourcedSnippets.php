<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

/**
 * Every PHP code block of a guide or the README that no snippet marker holds to
 * an executed example (SSO-12.5), by its document and its place among that
 * document's PHP blocks, with the reason the example harness cannot run it.
 * `ExampleSnippetsTest` fails on a PHP block that is neither marked nor listed
 * here, and on a listed block that is marked or gone, so this list is exactly
 * the documentation's code that no example runs. Only what the harness refuses
 * by design is listed: every other block is taken from an executed example.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnsourcedSnippets
{
    /** @var string A call of a sibling package's API, which this package does not install. */
    public const string SIBLING = 'sibling';

    /** @var string A schedule naming one of the package's models, which no example may name (`ExamplesUsePublicApiTest`); the model's own tests run it. */
    public const string MODEL = 'model';

    /** @var array<string, array<int, string>> Each document's unmarked PHP blocks, by their place among its PHP blocks (from 1), with their reason. */
    public const array FENCES = [
        'docs/guides/events.md'                       => [2 => self::SIBLING, 3 => self::SIBLING],
        'docs/guides/integrating-with-laravel-iam.md' => [4 => self::SIBLING, 5 => self::SIBLING],
        'docs/guides/rate-limits.md'                  => [2 => self::MODEL],
        'docs/guides/single-use-store.md'             => [2 => self::MODEL],
    ];
}
