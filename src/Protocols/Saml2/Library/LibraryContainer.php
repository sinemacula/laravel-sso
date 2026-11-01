<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\SAML2\Compat\ContainerSingleton;

/**
 * The container `simplesamlphp/saml2` reads its process-wide services from, set
 * once per process with nothing in it that changes, so it is safe under Octane
 * and in queue workers (SSO-11.2): every per-connection policy lives in the
 * per-call objects the adapter builds, never here.
 *
 * The package uses only the library's low-level parsing, schema, signature and
 * decryption calls (`docs/design/saml-library.md`), none of which needs the
 * library's clock, temporary files or redirects, so each of those fails closed
 * with a `LogicException` rather than reading the system's time or disk. The
 * logger discards everything and debug messages are dropped, so no message the
 * library might pass them ever reaches a log (SSO-9.8). Changing the blacklist
 * is refused: the adapter holds every algorithm to the connection's allow-list
 * itself.
 *
 * `ensure()` sets it when no container is set yet, and keeps a container an
 * application that uses the library itself has set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LibraryContainer extends AbstractContainer
{
    /** @var string Why a service the package never uses is refused. */
    private const string UNUSED = 'The SAML adapter never asks the library for its %s.';

    /**
     * Set the container, unless one is set already.
     *
     * @return void
     */
    public static function ensure(): void
    {
        if ((new \ReflectionProperty(ContainerSingleton::class, 'container'))->isInitialized()) {
            return;
        }

        ContainerSingleton::setContainer(new self);
    }

    /**
     * Refuse to change the blacklist: the adapter holds every algorithm to the
     * connection's allow-list.
     *
     * @param  ?array<mixed>  $algos
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S1172")
     */
    #[\Override]
    public function setBlacklistedAlgorithms(?array $algos): void
    {
        throw new \LogicException(sprintf(self::UNUSED, 'blacklist'));
    }

    /**
     * A logger that discards everything.
     *
     * @return \Psr\Log\LoggerInterface
     */
    #[\Override]
    public function getLogger(): LoggerInterface
    {
        return new NullLogger;
    }

    /**
     * Drop the debug message: a SAML message never reaches a log.
     *
     * @param  mixed  $message
     * @param  string  $type
     * @return void
     *
     * @SuppressWarnings("php:S1172")
     */
    #[\Override]
    public function debugMessage(mixed $message, string $type): void
    {
        // A SAML message is never logged
    }

    /**
     * Refuse: the package builds its own navigation.
     *
     * @param  string  $url
     * @param  array<mixed>  $data
     * @return string
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S1172")
     */
    #[\Override]
    public function getPOSTRedirectURL(string $url, array $data = []): string
    {
        throw new \LogicException(sprintf(self::UNUSED, 'redirects'));
    }

    /**
     * Refuse: the package writes no temporary file.
     *
     * @return string
     *
     * @throws \LogicException
     */
    #[\Override]
    public function getTempDir(): string
    {
        throw new \LogicException(sprintf(self::UNUSED, 'temporary directory'));
    }

    /**
     * Refuse: the package writes no file.
     *
     * @param  string  $filename
     * @param  string  $data
     * @param  ?int  $mode
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S1172")
     */
    #[\Override]
    public function writeFile(string $filename, string $data, ?int $mode = null): void
    {
        throw new \LogicException(sprintf(self::UNUSED, 'files'));
    }

    /**
     * Refuse: every time check reads the package's own clock (SSO-11.13).
     *
     * @return \Psr\Clock\ClockInterface
     *
     * @throws \LogicException
     */
    #[\Override]
    public function getClock(): ClockInterface
    {
        throw new \LogicException(sprintf(self::UNUSED, 'clock'));
    }
}
