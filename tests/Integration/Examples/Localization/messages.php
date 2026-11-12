<?php

declare(strict_types = 1);

/*
 * The messages read in `docs/guides/localization.md`; it answers the three
 * lines read.
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
