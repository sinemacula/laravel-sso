# Localisation

## Purpose

This note records which of the package's answers are words put in front of a consumer and which are codes, and how the
words are translated: through Laravel's translator, under the package's own namespace, so an application's translations
apply and a locale without one falls back to English (SSO-12.6).

## Invariants

- A message is something the package itself can show a person: the title, button and `noscript` text of the HTTP-POST
  page that sends an `AuthnRequest` (SSO-5.1, SSO-5.3), the body of the `400` a completion answers when no trusted
  redirect target is known (SSO-5.7), and the body of a completion's redirect (SSO-5.6). Each is a case of
  `Localization\Enums\Message`. Everything else the package answers with (a failure reason, a validation code, a
  configuration problem, an exception) is a machine-readable code or an operator's message, never translated, and the
  application words the codes itself.
- Every message is read through `Localization\Messages::get()`, never written inline: a new message adds a case and its
  English line.
- The lines live in the package's `lang/{locale}/messages.php`, loaded by the provider under the `sso` namespace, so a
  message's full key is `sso::messages.{case value}` (`sso::messages.post_navigation.title`). The case's value is the
  key in the file, and is stable once released: an application's override names it.
- Every case has a non-empty English line in `lang/en/messages.php`, and every line there is a case, so no message is
  shown as its key and no line is shipped that nothing reads.
- A message is read in the locale given, or the translator's current locale, read on each call; Laravel then reads the
  application's fallback locale (`app.fallback_locale`) as it does for any line. When neither has a line, the message
  is read again in English (`en`), whatever the application's fallback locale is: English is the package's own
  fallback, since English is the one locale it ships.
- A message with no English line either is a package bug, not an answer: `get()` throws a `LogicException` naming the
  key, rather than showing the key to a person.
- Replacements are Laravel's `:placeholder` replacements (with its `:Placeholder` and `:PLACEHOLDER` forms), passed to
  the translator unchanged.
- The answer is plain text. The English lines hold no markup, and nothing marks a line as safe: whoever renders a
  message in HTML escapes it (`e()`, `{{ }}`), since an application's translation, and a replacement above all, may
  hold anything.
- `Messages` is `final readonly` and keeps only the translator; it is not bound, so the container builds it with the
  application's translator wherever it is resolved, and the locale is read on each call. Nothing of one request or job
  outlives it under Octane or a queue worker (SSO-11.2).
- There is no configuration section and no boot check: the translations are always loaded, and publishing them is
  optional.

## Success Path

1. The provider's `boot()` calls `loadTranslationsFrom(lang/, 'sso')`, and in the console publishes `lang/` to the
   application's `lang/vendor/sso` under the `sso-lang` tag.
2. A caller resolves `Messages` and calls `get(Message::POST_NAVIGATION_TITLE)`, with replacements or a locale where
   it has them.
3. `get()` asks the translator for `sso::messages.post_navigation.title` in the locale, without replacements. Laravel
   reads the application's `lang/vendor/sso/{locale}/messages.php` over the package's lines for that locale, then the
   same for the application's fallback locale.
4. When the translator has a line, `get()` reads it again with the replacements and answers it. When the translator
   answers with the key itself, `get()` does the same in English, and throws when English has no line.
5. The caller escapes the answer where it renders it in HTML.

## Failure / Edge Cases

- A locale with a line for some messages and not others answers its own lines and English (or the application's
  fallback) for the rest.
- An application whose fallback locale is not English, and has no line in it either, still gets English, never the
  key.
- A replacement whose name appears in the key (`messages`, `m`) would turn a missing line's key into something else,
  which a check with replacements would take for a line; the presence of a line is therefore checked without them.
- An override file in `lang/vendor/sso/{locale}/messages.php` is merged over the package's lines for that locale
  (`array_replace_recursive`), so it may hold only the lines it changes.
- An application that sets a missing-key handler (`Lang::handleMissingKeysUsing()`) and answers a missing key with
  something other than the key makes that answer a line: the English fallback is not reached for that locale.
- A line an application overrides with an array is not a line, and falls back as a missing one does; one it overrides
  with an empty string is a line, and answers empty, as Laravel answers it.

## Implementation Anchors

- `src/Localization/Messages.php`.
- `src/Localization/Enums/Message.php`.
- `lang/en/messages.php`.
- `src/SsoServiceProvider.php`: `boot()` (`loadTranslationsFrom(__DIR__ . '/../lang', 'sso')`) and
  `registerPublishing()` (the `sso-lang` tag).

## Authoritative Tests

- `tests/Unit/Localization/Enums/MessageTest.php`.
- `tests/Feature/Localization/MessagesTest.php`.
- `tests/Integration/Localization/PublishedTranslationsTest.php`.
- `tests/Feature/SsoServiceProviderTest.php` `testTranslationsAreLoadedAndPublished`.
- `tests/Unit/Architecture/NamespaceDependenciesTest.php`, which scans `lang/` for a sibling package's namespace or
  configuration.

## Change Triggers

- A new message the package can show, or a message shown somewhere new.
- A change to a message's key, the namespace, the translation file's name or the publishing tag.
- A change to the fallback order, to the fallback locale, or to what a missing English line does.
- A line that holds markup, or a caller that renders a message without escaping it.
