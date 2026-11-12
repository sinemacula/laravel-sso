<?php

declare(strict_types = 1);

namespace Tests\Feature\Localization;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Arr;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Localization\Enums\Message;
use SineMacula\Laravel\Sso\Localization\Messages;
use Tests\TestCase;

/**
 * Feature tests for the package's translated messages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Messages::class)]
final class MessagesTest extends TestCase
{
    /**
     * Each message is its English line by default.
     *
     * @return void
     */
    public function testEachMessageIsItsEnglishLineByDefault(): void
    {
        /** @var array<array-key, mixed> $lines */
        $lines    = require dirname(__DIR__, 3) . '/lang/en/messages.php';
        $messages = $this->messages();

        foreach (Message::cases() as $message) {
            self::assertSame(Arr::get($lines, $message->value), $messages->get($message));
        }

        self::assertSame('Signing you in', $messages->get(Message::POST_NAVIGATION_TITLE));
    }

    /**
     * An application's translation applies in the locale current at each call.
     *
     * @return void
     */
    public function testAnApplicationsTranslationApplies(): void
    {
        $messages = $this->messages();

        $this->translator()->addLines(['messages.post_navigation.continue' => 'Continuer'], 'fr', 'sso');

        self::assertSame('Continue', $messages->get(Message::POST_NAVIGATION_CONTINUE));

        $this->app?->setLocale('fr');

        self::assertSame('Continuer', $messages->get(Message::POST_NAVIGATION_CONTINUE));
        self::assertSame('Signing you in', $messages->get(Message::POST_NAVIGATION_TITLE));
    }

    /**
     * A locale without a translation falls back to English.
     *
     * @return void
     */
    public function testAnUntranslatedLocaleFallsBackToEnglish(): void
    {
        $this->app?->setLocale('de');

        self::assertSame('Continue', $this->messages()->get(Message::POST_NAVIGATION_CONTINUE));
        self::assertSame('The sign-in response could not be accepted.', $this->messages()->get(Message::COMPLETION_INVALID));
    }

    /**
     * English answers whatever the application's fallback locale.
     *
     * @return void
     */
    public function testEnglishAnswersWhateverTheApplicationsFallback(): void
    {
        $this->app?->setFallbackLocale('de');
        $this->app?->setLocale('fr');

        self::assertSame('de', config('app.fallback_locale'));
        self::assertSame('Continue', $this->messages()->get(Message::POST_NAVIGATION_CONTINUE));
    }

    /**
     * The application's fallback locale is read before English.
     *
     * @return void
     */
    public function testTheApplicationsFallbackIsReadBeforeEnglish(): void
    {
        $this->translator()->addLines(['messages.post_navigation.continue' => 'Weiter'], 'de', 'sso');

        $this->app?->setFallbackLocale('de');
        $this->app?->setLocale('fr');

        self::assertSame('Weiter', $this->messages()->get(Message::POST_NAVIGATION_CONTINUE));
        self::assertSame('Signing you in', $this->messages()->get(Message::POST_NAVIGATION_TITLE));
    }

    /**
     * A locale given wins over the current locale.
     *
     * @return void
     */
    public function testAnExplicitLocaleWinsOverTheCurrentLocale(): void
    {
        $messages = $this->messages();

        $this->translator()->addLines(['messages.post_navigation.continue' => 'Continuer'], 'fr', 'sso');

        $this->app?->setLocale('de');

        self::assertSame('Continuer', $messages->get(Message::POST_NAVIGATION_CONTINUE, [], 'fr'));

        $this->app?->setLocale('fr');

        self::assertSame('Continue', $messages->get(Message::POST_NAVIGATION_CONTINUE, [], 'en'));
        self::assertSame('Continue', $messages->get(Message::POST_NAVIGATION_CONTINUE, [], 'de'));
    }

    /**
     * Laravel's `:placeholder` replacements apply, upper-case and capitalised
     * forms included.
     *
     * @return void
     */
    public function testReplacementsAreApplied(): void
    {
        $this->translator()->addLines(['messages.completion.redirecting' => 'Retour vers :name (:NAME, :Code).'], 'fr', 'sso');

        $line = $this->messages()->get(Message::COMPLETION_REDIRECTING, ['name' => 'Acme', 'code' => 'abc'], 'fr');

        self::assertSame('Retour vers Acme (ACME, Abc).', $line);
    }

    /**
     * A replacement cannot pass a missing line off as translated.
     *
     * @return void
     */
    public function testAReplacementDoesNotHideAMissingLine(): void
    {
        $this->app?->setLocale('de');

        $line = $this->messages()->get(Message::POST_NAVIGATION_TITLE, ['messages' => 'x', 'sso' => 'y', 'm' => 'z']);

        self::assertSame('Signing you in', $line);
    }

    /**
     * A message without an English line throws naming the key.
     *
     * @return void
     */
    public function testAMissingEnglishLineThrows(): void
    {
        $translator = $this->translator();
        $original   = $translator->getLoader()->namespaces()['sso'] ?? null;
        $directory  = sys_get_temp_dir() . '/' . uniqid('laravel-sso-', true);
        $files      = new Filesystem;

        self::assertIsString($original);

        $files->ensureDirectoryExists($directory . '/en');
        $files->put($directory . '/en/messages.php', "<?php\n\nreturn [];\n");

        try {
            $translator->addNamespace('sso', $directory);

            $this->expectException(\LogicException::class);
            $this->expectExceptionMessage('sso::messages.post_navigation.title');

            $this->messages()->get(Message::POST_NAVIGATION_TITLE, [], 'fr');
        } finally {
            $translator->addNamespace('sso', $original);

            $files->deleteDirectory($directory);
        }
    }

    /**
     * The messages, built by the container as a caller resolves them.
     *
     * @return \SineMacula\Laravel\Sso\Localization\Messages
     */
    private function messages(): Messages
    {
        $messages = $this->app?->make(Messages::class);

        self::assertInstanceOf(Messages::class, $messages);

        return $messages;
    }

    /**
     * The application's translator.
     *
     * @return \Illuminate\Translation\Translator
     */
    private function translator(): Translator
    {
        $translator = $this->app?->make('translator');

        self::assertInstanceOf(Translator::class, $translator);

        return $translator;
    }
}
