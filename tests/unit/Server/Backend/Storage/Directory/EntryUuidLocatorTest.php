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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Directory;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryUuidLocator;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class EntryUuidLocatorTest extends TestCase
{
    use ServerContainerTrait;

    private const UUID_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private const UUID_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

    private InMemoryStorage $storage;

    private EntryUuidLocator $subject;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->subject = new EntryUuidLocator(
            $this->storage,
            $this->fromContainer(FilterEvaluatorInterface::class),
        );
    }

    public function test_it_finds_the_entry_holding_the_uuid(): void
    {
        $this->store('cn=alice,dc=example,dc=com', self::UUID_A);

        self::assertSame(
            'cn=alice,dc=example,dc=com',
            $this->subject->findByUuid(self::UUID_A)?->getDn()->toString(),
        );
    }

    public function test_it_returns_null_when_no_entry_holds_the_uuid(): void
    {
        $this->store('cn=alice,dc=example,dc=com', self::UUID_A);

        self::assertNull($this->subject->findByUuid(self::UUID_B));
    }

    public function test_it_returns_the_matching_entry_when_others_are_in_scope(): void
    {
        $this->store('cn=alice,dc=example,dc=com', self::UUID_A);
        $this->store('cn=bob,dc=example,dc=com', self::UUID_B);

        self::assertSame(
            'cn=bob,dc=example,dc=com',
            $this->subject->findByUuid(self::UUID_B)?->getDn()->toString(),
        );
    }

    private function store(
        string $dn,
        string $uuid,
    ): void {
        $this->storage->store(new Entry(
            $dn,
            new Attribute('cn', 'x'),
            new Attribute('entryUUID', $uuid),
        ));
    }
}
