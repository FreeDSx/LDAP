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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Pdo;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Operation\UpdateEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class UpdateEntryHandlerTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private const ADMINS = 'cn=Admins,dc=example,dc=com';

    private UpdateEntryHandler $subject;

    private ReadEntryInterface $reader;

    protected function setUp(): void
    {
        $container = Container::forServer(TestServerOptions::sqlite());
        $this->subject = $container->get(UpdateEntryHandler::class);
        $this->reader = $container->get(ReadEntryInterface::class);

        $container->get(LdapImporter::class)->importEntries([
            new Entry(
                new Dn(self::BASE),
                new Attribute('dc', 'example'),
            ),
            $this->person('Bob'),
            $this->person('Carol'),
            new Entry(
                new Dn(self::ADMINS),
                new Attribute('objectClass', 'groupOfNames'),
                new Attribute('cn', 'Admins'),
                new Attribute('member', $this->dnOf('Bob')),
            ),
        ]);
    }

    public function test_adding_a_member_keeps_the_members_already_linked(): void
    {
        $this->modify(new Change(Change::TYPE_ADD, 'member', $this->dnOf('Carol')));

        self::assertEqualsCanonicalizing(
            [$this->dnOf('Bob'), $this->dnOf('Carol')],
            $this->members(),
        );
    }

    public function test_deleting_a_member_leaves_the_rest_linked(): void
    {
        $this->modify(new Change(Change::TYPE_ADD, 'member', $this->dnOf('Carol')));
        $this->modify(new Change(Change::TYPE_DELETE, 'member', $this->dnOf('Bob')));

        self::assertSame(
            [$this->dnOf('Carol')],
            $this->members(),
        );
    }

    public function test_replacing_the_members_writes_the_attribute_whole(): void
    {
        $this->modify(new Change(Change::TYPE_REPLACE, 'member', $this->dnOf('Carol')));

        self::assertSame(
            [$this->dnOf('Carol')],
            $this->members(),
        );
    }

    /**
     * @return list<string>
     */
    private function members(): array
    {
        return array_values(
            $this->reader
                ->find((new Dn(self::ADMINS))->normalize())
                ?->get('member')
                ?->getValues() ?? [],
        );
    }

    private function modify(Change ...$changes): void
    {
        $this->subject->handle(
            new UpdateCommand(
                new Dn(self::ADMINS),
                $changes,
            ),
            new WriteContext(
                new AnonToken(),
                new ControlBag(),
            ),
        );
    }

    private function person(string $cn): Entry
    {
        return new Entry(
            new Dn($this->dnOf($cn)),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', $cn),
            new Attribute('sn', $cn),
        );
    }

    private function dnOf(string $cn): string
    {
        return "cn={$cn}," . self::BASE;
    }
}
