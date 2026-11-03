<?php

declare(strict_types = 1);

/*
 * The messages read in `docs/guides/localization.md` (SSO-12.6, SSO-12.5), as
 * the application's page that posts an AuthnRequest, or its own completion
 * response, reads them: one in the current locale, one in a locale asked for,
 * and one with a replacement. `LocalizationExampleTest` runs it under the
 * application's translations and asserts the three lines it answers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start localization-messages
use SineMacula\Laravel\Sso\Localization\Enums\Message;
use SineMacula\Laravel\Sso\Localization\Messages;

$messages = app(Messages::class);

$title       = $messages->get(Message::POST_NAVIGATION_TITLE);                      // in the current locale
$french      = $messages->get(Message::POST_NAVIGATION_TITLE, [], 'fr');            // in French
$redirecting = $messages->get(Message::COMPLETION_REDIRECTING, ['name' => 'Acme']); // :name replaced, where a line has it
// @snippet-end localization-messages
return [$title, $french, $redirecting];
