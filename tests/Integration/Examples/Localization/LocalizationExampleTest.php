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
 * The examples of `docs/guides/localization.md`, with this directory's `lang`
 * as the application's.
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
     * Each message is read in its locale, and an unused replacement changes
     * nothing.
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
     * A line holding `:name` has it replaced; a missing line falls back to
     * English.
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
     * The English override rewords only the line it holds.
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
     * The French file translates every message; a locale with no file reads
     * English.
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
     * Without the application's lang directory, the messages are English.
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
     * Run the guide's reading of the messages in a scope of its own.
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
     * Make the directory the application's lang directory, forgetting the
     * translator so the next resolution reads it.
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
