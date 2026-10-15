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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * How an attribute's matching rule decides which values a write adds, keeps, or removes.
 */
trait ValueMatchingWriteTestsTrait
{
    public function testAddAcceptsAUniqueMemberCarryingAnIdentifier(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=uidgroup,dc=foo,dc=bar',
            [
                'cn' => 'uidgroup',
                'uniqueMember' => "cn=user,dc=foo,dc=bar#'0101'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'uniqueMember')
                ->base('cn=uidgroup,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ["cn=user,dc=foo,dc=bar#'0101'B"],
            $found->first()?->get('uniqueMember')?->getValues(),
        );

        $this->ldapClient()->delete('cn=uidgroup,dc=foo,dc=bar');
    }

    public function testAddRejectsAUniqueMemberWhoseNameIsNotADn(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=baduid,dc=foo,dc=bar',
            [
                'cn' => 'baduid',
                'uniqueMember' => "not a dn#'0101'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        ));
    }

    /**
     * RFC 4517 3.3.21 leaves '#' unescaped inside the name, so a tail that is not a bit string belongs to the DN.
     */
    public function testAddAcceptsAUniqueMemberWhoseTailIsNotABitString(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=notabitstring,dc=foo,dc=bar',
            [
                'cn' => 'notabitstring',
                'uniqueMember' => "cn=user,dc=foo,dc=bar#'0102'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'uniqueMember')
                ->base('cn=notabitstring,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ["cn=user,dc=foo,dc=bar#'0102'B"],
            $found->first()?->get('uniqueMember')?->getValues(),
        );

        $this->ldapClient()->delete('cn=notabitstring,dc=foo,dc=bar');
    }

    public function testUniqueMemberMatchesOnTheNameAndTheIdentifierTogether(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=uidmatch,dc=foo,dc=bar',
            [
                'cn' => 'uidmatch',
                'uniqueMember' => "cn=user,dc=foo,dc=bar#'0101'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        ));

        $matches = fn(string $assertion): int => count($this->ldapClient()->search(
            Operations::search(Filters::equal('uniqueMember', $assertion))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        ));

        self::assertSame(
            1,
            $matches("cn=user,dc=foo,dc=bar#'0101'B"),
        );
        // RFC 4517 4.2.34: absent from one side and present on the other is a mismatch.
        self::assertSame(
            0,
            $matches('cn=user,dc=foo,dc=bar'),
        );
        self::assertSame(
            0,
            $matches("cn=user,dc=foo,dc=bar#'1111'B"),
        );

        $this->ldapClient()->delete('cn=uidmatch,dc=foo,dc=bar');
    }

    public function testModifyAddOfACaseVariantOnACaseExactAttributeIsANewValue(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=exactadd,dc=foo,dc=bar',
            [
                'cn' => 'exactadd',
                'sn' => 'Exact',
                'labeledURI' => 'http://Example.COM/A',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->ldapClient()->send(Operations::modify(
            'cn=exactadd,dc=foo,dc=bar',
            Change::add(new Attribute('labeledURI', 'http://example.com/a')),
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'labeledURI')
                ->base('cn=exactadd,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertCount(
            2,
            $found->first()?->get('labeledURI')?->getValues() ?? [],
        );

        $this->ldapClient()->delete('cn=exactadd,dc=foo,dc=bar');
    }

    public function testModifyDeleteOfACaseVariantOnACaseExactAttributeIsRefused(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=exactdel,dc=foo,dc=bar',
            [
                'cn' => 'exactdel',
                'sn' => 'Exact',
                'labeledURI' => 'http://Example.COM/A',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        try {
            $this->ldapClient()->send(Operations::modify(
                'cn=exactdel,dc=foo,dc=bar',
                Change::delete(new Attribute('labeledURI', 'http://example.com/a')),
            ));
            self::fail('Deleting a value the entry does not hold should have been rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::NO_SUCH_ATTRIBUTE,
                $e->getCode(),
            );
        }

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'labeledURI')
                ->base('cn=exactdel,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['http://Example.COM/A'],
            $found->first()?->get('labeledURI')?->getValues(),
        );

        $this->ldapClient()->delete('cn=exactdel,dc=foo,dc=bar');
    }

    public function testModifyDeleteOfACaseVariantOnACaseIgnoreAttributeSucceeds(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=ignoredel,dc=foo,dc=bar',
            [
                'cn' => 'ignoredel',
                'sn' => 'Ignore',
                'description' => 'Hello World',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->ldapClient()->send(Operations::modify(
            'cn=ignoredel,dc=foo,dc=bar',
            Change::delete(new Attribute('description', 'hello world')),
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'description')
                ->base('cn=ignoredel,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertNull($found->first()?->get('description'));

        $this->ldapClient()->delete('cn=ignoredel,dc=foo,dc=bar');
    }

    public function testModifyDeleteFoldsInsignificantSpaceOnACaseIgnoreAttribute(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=spacedel,dc=foo,dc=bar',
            [
                'cn' => 'spacedel',
                'sn' => 'Space',
                'description' => 'Hello World',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        // RFC 4518 §2.6.1 folds inner whitespace, so the doubled space names the stored value.
        $this->ldapClient()->send(Operations::modify(
            'cn=spacedel,dc=foo,dc=bar',
            Change::delete(new Attribute('description', 'Hello  World')),
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'description')
                ->base('cn=spacedel,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertNull($found->first()?->get('description'));

        $this->ldapClient()->delete('cn=spacedel,dc=foo,dc=bar');
    }
}
