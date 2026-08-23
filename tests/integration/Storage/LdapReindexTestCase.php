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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use Closure;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use PHPUnit\Framework\TestCase;
use Swoole\Coroutine;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\TestWorker;
use Throwable;

/**
 * Reindexing reads and writes from inside one transaction, so the runner it runs under decides what answers it.
 */
abstract class LdapReindexTestCase extends TestCase
{
    use RequiresExtensionsTrait;

    protected const SEED = <<<LDIF
        version: 1

        dn: dc=foo,dc=bar
        objectClass: domain
        dc: foo

        dn: cn=admins,dc=foo,dc=bar
        objectClass: groupOfNames
        cn: admins
        member: CN=Admin, DC=Foo, DC=Bar

        LDIF;

    protected string $path;

    protected function setUp(): void
    {
        $this->requireRunnerExtension();

        $this->path = TestWorker::path($this->databaseName());
        $this->removeDatabase();
    }

    protected function tearDown(): void
    {
        $this->removeDatabase();
    }

    public function test_reindex_preserves_entry_attributes(): void
    {
        $this->withServer(function (LdapServer $server, EntryStorageInterface $storage): void {
            $dn = new Dn('cn=admins,dc=foo,dc=bar');
            $before = $storage->find($dn);
            self::assertNotNull($before);

            $server->reindex();

            $after = $storage->find($dn);
            self::assertNotNull($after);
            self::assertEquals(
                $before->toArray(),
                $after->toArray(),
            );
        });
    }

    /**
     * Names the database file, so two runners under one worker never share it.
     */
    abstract protected function databaseName(): string;

    abstract protected function storageConfig(): StorageConfigInterface;

    abstract protected function runnerMode(): RunnerMode;

    /**
     * Seeds a server and hands the body that server plus the storage it was built on.
     *
     * @param Closure(LdapServer, EntryStorageInterface): void $body
     */
    protected function withServer(Closure $body): void
    {
        $this->inRuntime(function () use ($body): void {
            $options = (TestServerOptions::defaults())
                ->setStorageConfig($this->storageConfig())
                ->setRunnerConfig(new RunnerConfig($this->runnerMode()));
            $container = Container::forServer($options);

            $server = new LdapServer($options, $container);
            $server->seed(new StringLdifLoader(self::SEED));

            $body(
                $server,
                $container->get(EntryStorageInterface::class),
            );
        });
    }

    /**
     * @return list<string>
     */
    protected function dnsMatching(
        EntryStorageInterface $storage,
        FilterInterface $filter,
    ): array {
        $entries = $storage->list(new StorageListOptions(
            baseDn: new Dn('dc=foo,dc=bar'),
            subtree: true,
            filter: $filter,
        ))->entries;

        $dns = [];
        foreach ($entries as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    protected function removeDatabase(): void
    {
        // Teardown still runs when setUp skipped before naming a database.
        if (!isset($this->path)) {
            return;
        }

        foreach (['', '-wal', '-shm'] as $suffix) {
            $file = $this->path . $suffix;
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }

    /**
     * Reindexing is only reachable through a server, so a runner the platform cannot host is nothing to assert about.
     */
    private function requireRunnerExtension(): void
    {
        match ($this->runnerMode()) {
            RunnerMode::Swoole => $this->requireSwoole(),
            RunnerMode::Pcntl => $this->requirePcntl(),
        };
    }

    /**
     * The Swoole assembly caches connections per coroutine, so everything it builds has to live inside one.
     *
     * @param Closure(): void $body
     */
    private function inRuntime(Closure $body): void
    {
        if ($this->runnerMode() !== RunnerMode::Swoole) {
            $body();

            return;
        }

        $error = null;

        // Carried out rather than thrown inside, where an assertion failure would escape PHPUnit as a coroutine fatal.
        Coroutine\run(static function () use ($body, &$error): void {
            try {
                $body();
            } catch (Throwable $e) {
                $error = $e;
            }
        });

        if ($error !== null) {
            throw $error;
        }
    }
}
