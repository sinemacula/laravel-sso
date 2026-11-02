<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;

/**
 * Whether the bound `Contracts\Linker` is backed by `Contracts\LinkStorage`
 * (SSO-8.8, `docs/design/linking.md`), the one place the pairing is judged.
 * Whatever writes a link asks here before it writes, so no row is ever written
 * that the resolver ignores.
 *
 * It resolves the linker from the container on each call, keeping nothing of
 * one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkStorageBinding
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the bound linker on each call. */
        private Container $container,
    ) {}

    /**
     * The storage the bound linker is, or `null` when it is not backed by one.
     *
     * @return ?\SineMacula\Laravel\Sso\Contracts\LinkStorage
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function find(): ?LinkStorage
    {
        $linker = $this->container->make(Linker::class);

        return $linker instanceof LinkStorage ? $linker : null;
    }

    /**
     * The storage the bound linker is, refusing what needs it otherwise.
     *
     * @param  string  $operation
     * @return \SineMacula\Laravel\Sso\Contracts\LinkStorage
     *
     * @throws \LogicException
     */
    public function require(string $operation): LinkStorage
    {
        return $this->find() ?? throw new \LogicException(self::problem($operation, $this->container->make(Linker::class)));
    }

    /**
     * What is wrong with the pairing, naming the linker's class and no value.
     *
     * @param  string  $operation
     * @param  \SineMacula\Laravel\Sso\Contracts\Linker  $linker
     * @return string
     */
    public static function problem(string $operation, Linker $linker): string
    {
        return sprintf(
            '%s needs links its resolver reads, but the [%s] bound as [%s] does not implement [%s]: bind [%s], or a wrapper that delegates to it.',
            $operation,
            $linker::class,
            Linker::class,
            LinkStorage::class,
            LinkStore::class,
        );
    }
}
