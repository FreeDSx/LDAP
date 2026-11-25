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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Linked values naming no stored entry, accepted only by a backend keeping them as written.
 */
trait LinkedValueAsWrittenTestsTrait
{
    public function testAddAcceptsAUniqueMemberWhoseTailIsNotABitString(): void
    {
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            'cn=notabitstring,dc=foo,dc=bar',
            [
                'cn' => 'notabitstring',
                'uniqueMember' => "cn=user,dc=foo,dc=bar#'0102'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        )));

        $found = $this->ldapClient()->read(
            'cn=notabitstring,dc=foo,dc=bar',
            ['uniqueMember'],
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=notabitstring,dc=foo,dc=bar'));

        self::assertSame(
            ["cn=user,dc=foo,dc=bar#'0102'B"],
            $found?->get('uniqueMember')?->getValues(),
        );
    }

    public function testUniqueMemberKeepsAnEscapedHashInTheName(): void
    {
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            'cn=uidescape,dc=foo,dc=bar',
            [
                'cn' => 'uidescape',
                'uniqueMember' => "cn=user,dc=foo,dc=bar\\\\#'0101'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        )));

        $matches = fn(string $assertion): int => count($this->ldapClient()->search(
            Operations::search(Filters::equal(
                'uniqueMember',
                $assertion,
            ))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        ));
        $withUid = $matches("cn=user,dc=foo,dc=bar\\\\#'0101'B");
        $escaped = $matches("cn=user,dc=foo,dc=bar\\#'0101'B");

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=uidescape,dc=foo,dc=bar'));

        self::assertSame(
            [1, 0],
            [$withUid, $escaped],
        );
    }
}
