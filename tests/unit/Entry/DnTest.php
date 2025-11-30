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

namespace Tests\Unit\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;
use PHPUnit\Framework\TestCase;

class DnTest extends TestCase
{
    private Dn $subject;

    protected function setUp(): void
    {
        $this->subject = new Dn('cn=fo\,o, dc=local,dc=example');
    }

    public function test_it_should_get_all_pieces_as_an_array_of_RDNs(): void
    {
        self::assertEquals(
            [
                new Rdn("cn", "fo\,o"),
                new Rdn("dc", "local"),
                new Rdn("dc", "example"),
            ],
            $this->subject->toArray(),
        );
    }

    public function test_it_should_get_the_parent_dn(): void
    {
        self::assertEquals(
            new Dn('dc=local,dc=example'),
            $this->subject->getParent(),
        );
    }

    public function test_it_should_get_the_rdn(): void
    {
        self::assertEquals(
            new Rdn('cn', 'fo\,o'),
            $this->subject->getRdn(),
        );
    }

    public function test_it_should_return_a_count(): void
    {
        self::assertEquals(
            3,
            $this->subject->count()
        );
    }

    public function test_it_should_get_the_string_representation(): void
    {
        self::assertSame(
            'cn=fo\,o, dc=local,dc=example',
            $this->subject->toString(),
        );
    }

    public function test_it_should_check_if_it_is_a_valid_dn(): void
    {
        self::assertTrue(Dn::isValid('cn=foo,dc=bar,dc=foo'));
        self::assertFalse(Dn::isValid('foo'));
        self::assertTrue(Dn::isValid(''));
    }

    public function test_it_should_handle_a_rootdse_as_a_dn(): void
    {
        $this->subject = new Dn('');

        self::assertSame(
            '',
            $this->subject->toString(),
        );
        self::assertSame(
            [],
            $this->subject->toArray(),
        );
        self::assertCount(
            0,
            $this->subject,
        );
        self::assertNull($this->subject->getParent());
    }
}
