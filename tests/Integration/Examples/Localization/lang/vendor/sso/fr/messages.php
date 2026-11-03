<?php

declare(strict_types = 1);

/*
 * The application's French translation of `docs/guides/localization.md`
 * (SSO-12.6, SSO-12.5), at `lang/vendor/sso/fr/messages.php`: every message in
 * French. `LocalizationExampleTest` makes this directory's `lang` the
 * application's, as Laravel reads it, and reads each message in French through
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start localization-french
return [
    'post_navigation' => [
        'title'    => 'Connexion en cours',
        'continue' => 'Continuer',
        'noscript' => 'JavaScript est désactivé dans votre navigateur. Sélectionnez Continuer pour terminer la connexion.',
    ],
    'completion' => [
        'invalid'     => 'La réponse de connexion n’a pas pu être acceptée.',
        'redirecting' => 'Retour vers l’application.',
    ],
];
// @snippet-end localization-french
