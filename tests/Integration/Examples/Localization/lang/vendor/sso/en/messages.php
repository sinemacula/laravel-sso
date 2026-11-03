<?php

declare(strict_types = 1);

/*
 * The application's English override of `docs/guides/localization.md`
 * (SSO-12.6, SSO-12.5), at `lang/vendor/sso/en/messages.php`: one line
 * reworded, every other left to the package's. `LocalizationExampleTest` makes
 * this directory's `lang` the application's, as Laravel reads it, and reads the
 * messages through it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start localization-override
return [
    'post_navigation' => [
        'continue' => 'Carry on',
    ],
];
// @snippet-end localization-override
