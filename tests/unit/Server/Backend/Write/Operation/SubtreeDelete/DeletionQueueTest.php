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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Operation\SubtreeDelete;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Write\Operation\SubtreeDelete\DeletionQueue;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

final class DeletionQueueTest extends TestCase
{
    private DeletionQueue $subject;

    protected function setUp(): void
    {
        $storage = EntryFixture::inMemoryStorage(
            new Entry(new Dn('dc=example,dc=com')),
            new Entry(new Dn('ou=p,dc=example,dc=com')),
            new Entry(new Dn('cn=c1,ou=p,dc=example,dc=com')),
            new Entry(new Dn('ou=q,dc=example,dc=com')),
            new Entry(new Dn('cn=s,ou=q,dc=example,dc=com')),
            new Entry(new Dn('cn=t,cn=s,ou=q,dc=example,dc=com')),
        );
        $this->subject = new DeletionQueue(
            new SubtreeEnumerator($storage),
            new Dn('ou=p,dc=example,dc=com'),
        );
    }

    public function test_next_takes_no_more_than_it_is_asked_for(): void
    {
        self::assertSame(
            ['cn=c1,ou=p,dc=example,dc=com'],
            $this->subject->next(1),
        );
        self::assertSame(
            ['ou=p,dc=example,dc=com'],
            $this->subject->next(10),
        );
    }

    public function test_a_drained_queue_has_nothing_next(): void
    {
        $this->subject->next(10);

        self::assertSame(
            [],
            $this->subject->next(10),
        );
    }

    public function test_requeued_strays_come_first_then_the_members_they_blocked_then_the_rest(): void
    {
        $this->subject->next(1);

        $this->subject->requeue(
            ['cn=s,ou=q,dc=example,dc=com'],
            ['cn=c1,ou=p,dc=example,dc=com'],
        );

        self::assertSame(
            [
                'cn=t,cn=s,ou=q,dc=example,dc=com',
                'cn=s,ou=q,dc=example,dc=com',
                'cn=c1,ou=p,dc=example,dc=com',
                'ou=p,dc=example,dc=com',
            ],
            $this->subject->next(10),
        );
    }

    public function test_the_members_a_stray_blocks_are_its_parent_and_those_above_it(): void
    {
        self::assertSame(
            [
                'cn=a,ou=x,ou=p,dc=example,dc=com',
                'ou=x,ou=p,dc=example,dc=com',
                'ou=p,dc=example,dc=com',
            ],
            DeletionQueue::blockedBy(
                [
                    'cn=a,ou=x,ou=p,dc=example,dc=com',
                    'cn=b,ou=x,ou=p,dc=example,dc=com',
                    'ou=x,ou=p,dc=example,dc=com',
                    'cn=c,ou=p,dc=example,dc=com',
                    'ou=p,dc=example,dc=com',
                ],
                ['cn=stray,cn=a,ou=x,ou=p,dc=example,dc=com'],
            ),
        );
    }

    public function test_no_member_is_blocked_without_a_stray(): void
    {
        self::assertSame(
            [],
            DeletionQueue::blockedBy(
                [
                    'cn=a,ou=p,dc=example,dc=com',
                    'ou=p,dc=example,dc=com',
                ],
                [],
            ),
        );
    }
}
