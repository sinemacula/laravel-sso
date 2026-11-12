<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\SAML2\Compat\ContainerSingleton;

/**
 * The stateless process-wide container `simplesamlphp/saml2` reads. Services
 * the package never uses throw rather than touch the system clock or disk.
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

    /** @var string Why a container something else set is refused. */
    private const string FOREIGN = 'The SAML library\'s process-wide container is already set to [%s], not the package\'s own: '
        . 'the package runs SAML only through the container it sets itself.';

    /**
     * Set the package's container if none is set. A foreign one is refused, as
     * its clock, logger and blacklist would apply to every message.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public static function ensure(): void
    {
        if (!(new \ReflectionProperty(ContainerSingleton::class, 'container'))->isInitialized()) {
            ContainerSingleton::setContainer(new self);

            return;
        }

        $container = ContainerSingleton::getInstance();

        if (!$container instanceof self) {
            throw new \LogicException(sprintf(self::FOREIGN, $container::class));
        }
    }

    /**
     * Refuse: the adapter enforces each connection's algorithm allow-list.
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
     * Refuse: every time check reads the package's own clock.
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

    /**
     * Refuse: the package reads only posted responses, which are not deflated.
     *
     * @return int
     *
     * @throws \LogicException
     */
    #[\Override]
    public function getInflateSizeLimit(): int
    {
        throw new \LogicException(sprintf(self::UNUSED, 'inflate size limit'));
    }
}
