<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Localization;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\App;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Localization\Enums\Message;
use SineMacula\Laravel\Sso\Localization\Messages;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/localization.md` (SSO-12.6, SSO-12.5), on the
 * shared example harness, with this directory's `lang` as the application's
 * lang directory: the messages read in the current locale, in French and with a
 * replacement, the English override of one line, and the French translation of
 * every message. Each asserts the lines read and the fallback: a line a file
 * leaves out, and a locale with no file, read in English rather than as a
 * translation key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Messages::class)]
final class LocalizationExampleTest extends ExampleTestCase
{
    /** @var string The lang directory the test application had before. */
    private string $originalLangPath;

    /**
     * Make this directory's `lang` the application's lang directory.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->originalLangPath = app()->langPath();

        $this->switchLangDirectory(__DIR__ . '/lang');
    }

    /**
     * Give the test application its lang directory back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->switchLangDirectory($this->originalLangPath);

        parent::tearDown();
    }

    /**
     * In English, the title is the package's line, read in French it is the
     * application's translation, and a replacement the line does not hold
     * leaves the line as it is.
     *
     * @return void
     */
    public function testTheMessagesAreReadInTheirLocale(): void
    {
        [$title, $french, $redirecting] = $this->readMessages();

        self::assertSame('Signing you in', $title);
        self::assertSame('Connexion en cours', $french);
        self::assertSame('Returning you to the application.', $redirecting);
    }

    /**
     * With French the current locale, every message is read in French.
     *
     * @return void
     */
    public function testTheCurrentLocaleIsRead(): void
    {
        App::setLocale('fr');

        [$title, $french, $redirecting] = $this->readMessages();

        self::assertSame('Connexion en cours', $title);
        self::assertSame('Connexion en cours', $french);
        self::assertSame('Retour vers l’application.', $redirecting);
    }

    /**
     * A line of the application's that holds `:name` has it replaced, while a
     * message that locale has no line for is read in English, never as its key.
     *
     * @return void
     */
    public function testAReplacementFillsALineThatHoldsIt(): void
    {
        App::setLocale('de');

        app('translator')->addLines(['messages.completion.redirecting' => 'Zurück zu :name.'], 'de', 'sso');

        [$title, $french, $redirecting] = $this->readMessages();

        self::assertSame('Zurück zu Acme.', $redirecting);
        self::assertSame('Signing you in', $title);
        self::assertSame('Connexion en cours', $french);
    }

    /**
     * The English override rewords the one line it holds, and every line it
     * leaves out is the package's.
     *
     * @return void
     */
    public function testTheEnglishOverrideRewordsOneLine(): void
    {
        $messages = app(Messages::class);

        self::assertSame('Carry on', $messages->get(Message::POST_NAVIGATION_CONTINUE));
        self::assertSame('Signing you in', $messages->get(Message::POST_NAVIGATION_TITLE));
        self::assertSame('JavaScript is turned off in your browser. Select Continue to finish signing in.', $messages->get(Message::POST_NAVIGATION_NOSCRIPT));
        self::assertSame('The sign-in response could not be accepted.', $messages->get(Message::COMPLETION_INVALID));
    }

    /**
     * The French file translates every message, while a locale with no file is
     * read in English, the override included, never as a key.
     *
     * @return void
     */
    public function testTheFrenchFileTranslatesEveryMessage(): void
    {
        /** @var array<array-key, mixed> $french */
        $french   = require __DIR__ . '/lang/vendor/sso/fr/messages.php';
        $messages = app(Messages::class);

        foreach (Message::cases() as $message) {
            self::assertSame(Arr::get($french, $message->value), $messages->get($message, [], 'fr'));
        }

        self::assertSame('La réponse de connexion n’a pas pu être acceptée.', $messages->get(Message::COMPLETION_INVALID, [], 'fr'));
        self::assertSame('Carry on', $messages->get(Message::POST_NAVIGATION_CONTINUE, [], 'es'));
        self::assertSame('Signing you in', $messages->get(Message::POST_NAVIGATION_TITLE, [], 'es'));
    }

    /**
     * Without the application's lang directory, French has no line, and the
     * messages are the package's English.
     *
     * @return void
     */
    public function testWithoutTheApplicationsFilesTheMessagesAreEnglish(): void
    {
        $this->switchLangDirectory($this->originalLangPath);

        $messages = app(Messages::class);

        self::assertSame('Signing you in', $messages->get(Message::POST_NAVIGATION_TITLE, [], 'fr'));
        self::assertSame('Continue', $messages->get(Message::POST_NAVIGATION_CONTINUE));
    }

    /**
     * Run the guide's reading of the messages, in a scope of its own, and
     * answer the three lines it read.
     *
     * @return array{0: string, 1: string, 2: string}
     */
    private function readMessages(): array
    {
        /** @var array{0: string, 1: string, 2: string} $read */
        $read = require __DIR__ . '/messages.php';

        return $read;
    }

    /**
     * Make the directory the application's lang directory, and forget the
     * translator and its loader, so the next to resolve them reads it, as an
     * application booting with it does.
     *
     * @param  string  $path
     * @return void
     */
    private function switchLangDirectory(string $path): void
    {
        app()->useLangPath($path);
        app()->forgetInstance('translation.loader');
        app()->forgetInstance('translator');
    }
}
