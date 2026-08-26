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

namespace Tests\Support\FreeDSx\Ldap\Backend\Write;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Write\Operation\AddEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\DeleteEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\MoveEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\UpdateEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

/**
 * Builds one object graph per test, so a handler and the backend that reads its result share their storage.
 */
trait WriteHandlerTestTrait
{
    use ServerContainerTrait;

    private Container $graph;

    private EntryStorageInterface $storage;

    private Entry $alice;

    private Entry $bob;

    private Entry $base;

    /**
     * @param array<class-string, object> $sharedInstances
     */
    private function writeGraph(
        ?EntryStorageInterface $storage = null,
        ?ServerOptions $options = null,
        array $sharedInstances = [],
    ): void {
        $this->storage = $storage ?? new InMemoryStorage($this->fixture());
        $this->graph = $this->containerFor(
            $this->storage,
            $options,
            $sharedInstances,
        );
    }

    /**
     * What a handler left behind, read straight off storage rather than through anything that interprets it.
     */
    private function find(string $dn): ?Entry
    {
        return $this->storage->find((new Dn($dn))->normalize());
    }

    /**
     * @return list<Entry> the shared fixture, which puts cn=Bob under an ou=People that is deliberately absent
     */
    private function fixture(): array
    {
        $this->base = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
            new Attribute('objectClass', 'dcObject'),
        );
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('userPassword', 'secret'),
        );
        $this->bob = new Entry(
            new Dn('cn=Bob,ou=People,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Bob'),
        );

        return [
            $this->base,
            $this->alice,
            $this->bob,
        ];
    }

    private function adds(): AddEntryHandler
    {
        return $this->graph->get(AddEntryHandler::class);
    }

    private function deletes(): DeleteEntryHandler
    {
        return $this->graph->get(DeleteEntryHandler::class);
    }

    private function updates(): UpdateEntryHandler
    {
        return $this->graph->get(UpdateEntryHandler::class);
    }

    private function moves(): MoveEntryHandler
    {
        return $this->graph->get(MoveEntryHandler::class);
    }

    private function context(): WriteContext
    {
        return new WriteContext(
            new AnonToken(),
            new ControlBag(),
        );
    }

    private function systemContext(): WriteContext
    {
        return WriteContext::system(
            new AnonToken(),
            new ControlBag(),
        );
    }
}
