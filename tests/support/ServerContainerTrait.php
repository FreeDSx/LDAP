<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\StorageReadBackend;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

/**
 * Resolves real collaborators from the production wiring, so tests do not restate what the providers already build.
 */
trait ServerContainerTrait
{
    private ?Container $container = null;

    private ?ServerOptions $serverOptions = null;

    /**
     * Real collaborators pinned in place of the ones the providers build; a mock belongs in setUp instead.
     *
     * @return array<class-string, object>
     */
    protected function containerOverrides(): array
    {
        return [];
    }

    /**
     * Defaults to what a real server runs, so relaxing anything is a choice a test states rather than one it inherits.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::defaults();
    }

    /**
     * The one options instance this test's container reads, so tweaking it before resolving takes effect.
     */
    private function serverOptions(): ServerOptions
    {
        return $this->serverOptions ??= $this->makeServerOptions();
    }

    /**
     * Resolves from this test's container, or from a one-off container when options or collaborators are given.
     *
     * Configuration cannot be pinned through $sharedInstances, since the seeded options always win; pass $options.
     *
     * @template T of object
     * @param class-string<T> $className
     * @param array<class-string, object> $sharedInstances
     * @return T
     */
    private function fromContainer(
        string $className,
        array $sharedInstances = [],
        ?ServerOptions $options = null,
    ): object {
        if ($sharedInstances !== [] || $options !== null) {
            return Container::forServer(
                $options ?? $this->serverOptions(),
                $sharedInstances,
            )->get($className);
        }

        return $this->container()->get($className);
    }

    /**
     * The storage adapter the providers build for the given configuration.
     */
    private function storageFor(ServerOptions $options): EntryStorageInterface
    {
        return $this->fromContainer(
            EntryStorageInterface::class,
            options: $options,
        );
    }

    /**
     * The backend the providers build over the given storage, which is the collaborator these tests vary.
     */
    private function backendFor(
        EntryStorageInterface $storage,
        ?ServerOptions $options = null,
    ): StorageReadBackend {
        return $this->fromContainer(
            StorageReadBackend::class,
            [EntryStorageInterface::class => $storage],
            $options,
        );
    }

    /**
     * A container over the given storage, for pulling several collaborators that must share one graph.
     *
     * @param array<class-string, object> $sharedInstances
     */
    private function containerFor(
        EntryStorageInterface $storage,
        ?ServerOptions $options = null,
        array $sharedInstances = [],
    ): Container {
        return Container::forServer(
            $options ?? $this->serverOptions(),
            [EntryStorageInterface::class => $storage] + $sharedInstances,
        );
    }

    /**
     * This test's container, for pulling several services that must come from the same graph.
     */
    private function container(): Container
    {
        return $this->container ??= Container::forServer(
            $this->serverOptions(),
            $this->containerOverrides(),
        );
    }
}
