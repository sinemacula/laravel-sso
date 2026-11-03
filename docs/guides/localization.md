# Localisation

The package puts very few words in front of a person: the bodies of a completion's answers. It also ships the words for
the page your client builds to send a SAML `AuthnRequest` by HTTP-POST: the package never renders that page, since a
`post` navigation is a URL and fields ([Starting a Flow](starting-a-flow.md#the-answer)), but its lines are here for the
page you build. Every one of them goes through Laravel's translator under the package's `sso` namespace, so your
translations apply, and a locale you have not translated falls back to English.

Everything else the package answers with is a code, not a message: a failure reason (`signature_invalid`,
`request_expired`), a validation code, the code a failure redirect carries. Word those yourself, in your own
translation files, where you show them.

## The messages

Each message is a case of `SineMacula\Laravel\Sso\Localization\Enums\Message`. Its value is the line's key in the
package's `messages` file, so its full translation key is `sso::messages.{key}`.

| Case                       | Key                        | English                                                                         | Where it appears                                                                               |
|----------------------------|----------------------------|---------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| `POST_NAVIGATION_TITLE`    | `post_navigation.title`    | Signing you in                                                                  | The title of the page your client builds to post an `AuthnRequest` by HTTP-POST                |
| `POST_NAVIGATION_CONTINUE` | `post_navigation.continue` | Continue                                                                        | The button on that page, for a browser that does not post the request itself                   |
| `POST_NAVIGATION_NOSCRIPT` | `post_navigation.noscript` | JavaScript is turned off in your browser. Select Continue to finish signing in. | The text on that page shown when JavaScript is turned off                                      |
| `COMPLETION_INVALID`       | `completion.invalid`       | The sign-in response could not be accepted.                                     | The body of the `400` a completion answers when no trusted redirect target is known            |
| `COMPLETION_REDIRECTING`   | `completion.redirecting`   | Returning you to the application.                                               | The body of a completion's redirect to your redirect URI, for a client that does not follow it |

## Reading a message

Resolve `SineMacula\Laravel\Sso\Localization\Messages` from the container and ask it for a message:

<!-- snippet: tests/Integration/Examples/Localization/messages.php#localization-messages -->
```php
use SineMacula\Laravel\Sso\Localization\Enums\Message;
use SineMacula\Laravel\Sso\Localization\Messages;

$messages = app(Messages::class);

$title       = $messages->get(Message::POST_NAVIGATION_TITLE);                      // in the current locale
$french      = $messages->get(Message::POST_NAVIGATION_TITLE, [], 'fr');            // in French
$redirecting = $messages->get(Message::COMPLETION_REDIRECTING, ['name' => 'Acme']); // :name replaced, where a line has it
```

A message is read in the locale you give, or the current locale (`App::setLocale()`), then in your
`app.fallback_locale`, as Laravel reads any line. When neither has a line, it is read in English, even when your
fallback locale is another one, so a person is never shown a translation key. Replacements are Laravel's own
`:placeholder` replacements, `:Placeholder` and `:PLACEHOLDER` included.

The answer is plain text. Escape it wherever you put it in HTML (`{{ $message }}` in Blade, or `e()`): a translation,
and a replacement above all, may hold anything.

## Publishing the translations

Publish the package's lines to `lang/vendor/sso` to start from them:

```bash
php artisan vendor:publish --tag=sso-lang
```

This writes `lang/vendor/sso/en/messages.php`. Publishing is optional: you can create the files under
`lang/vendor/sso` yourself.

## Overriding lines per locale

Laravel reads `lang/vendor/sso/{locale}/messages.php` over the package's lines for that locale, merging the two, so a
file needs only the lines it changes. To change the English wording of one message, in
`lang/vendor/sso/en/messages.php`:

<!-- snippet: tests/Integration/Examples/Localization/lang/vendor/sso/en/messages.php#localization-override -->
```php
return [
    'post_navigation' => [
        'continue' => 'Carry on',
    ],
];
```

To translate the messages into another locale, add a file for it, here `lang/vendor/sso/fr/messages.php`:

<!-- snippet: tests/Integration/Examples/Localization/lang/vendor/sso/fr/messages.php#localization-french -->
```php
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
```

A message your file leaves out is read in your fallback locale, then in English. Keep the lines plain text: no HTML,
since whoever renders them escapes them.

A package upgrade that adds a message adds its English line, so a locale you have translated shows that one message in
English until you add it to your file.
