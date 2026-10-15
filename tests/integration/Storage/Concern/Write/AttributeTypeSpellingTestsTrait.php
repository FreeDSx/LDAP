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
 * Attribute types spelled by an alias or a numeric OID, in entries, DNs, filters, compares, and bind names.
 */
trait AttributeTypeSpellingTestsTrait
{
    public function testAnAddSpelledWithAliasesIsStoredUnderThePrimaryNames(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'commonName=Alias Spelled,dc=foo,dc=bar',
            ['commonName' => 'Alias Spelled', 'surname' => 'Alias', 'objectClass' => 'inetOrgPerson'],
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn', 'sn')
                ->base('cn=Alias Spelled,dc=foo,dc=bar')
                ->useBaseScope(),
        )->first();

        self::assertNotNull($found);
        self::assertSame(
            'cn=Alias Spelled,dc=foo,dc=bar',
            $found->getDn()->toString(),
        );
        $descriptions = array_map(
            static fn(Attribute $attribute): string => $attribute->getDescription(),
            $found->getAttributes(),
        );
        sort($descriptions);
        self::assertSame(
            ['cn', 'sn'],
            $descriptions,
        );

        $this->ldapClient()->delete('2.5.4.3=Alias Spelled,dc=foo,dc=bar');
        self::assertNull($this->ldapClient()->read('cn=Alias Spelled,dc=foo,dc=bar'));
    }

    public function testAnEntryCannotBeAddedAgainUnderANumericOidSpellingOfItsNamingType(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=Spelled Twice,dc=foo,dc=bar',
            ['cn' => 'Spelled Twice', 'sn' => 'Twice', 'objectClass' => 'inetOrgPerson'],
        ));

        try {
            $this->ldapClient()->create(Entry::fromArray(
                '2.5.4.3=Spelled Twice,dc=foo,dc=bar',
                ['cn' => 'Spelled Twice', 'sn' => 'Twice', 'objectClass' => 'inetOrgPerson'],
            ));
            self::fail('The numeric OID spelling should have named the entry already added.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ENTRY_ALREADY_EXISTS,
                $e->getCode(),
            );
        } finally {
            $this->ldapClient()->delete('cn=Spelled Twice,dc=foo,dc=bar');
        }
    }

    public function testModifyAndRenameReachAnEntryThroughAnAliasSpelledDn(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=Reach Me,dc=foo,dc=bar',
            ['cn' => 'Reach Me', 'sn' => 'Reach', 'objectClass' => 'inetOrgPerson'],
        ));

        $this->ldapClient()->send(Operations::modify(
            'commonName=Reach Me,dc=foo,dc=bar',
            Change::replace(new Attribute('surname', 'Reached')),
        ));
        $this->ldapClient()->rename('commonName=Reach Me,dc=foo,dc=bar', 'commonName=Reached', true);

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn', 'sn')
                ->base('cn=Reached,dc=foo,dc=bar')
                ->useBaseScope(),
        )->first();

        self::assertNotNull($found);
        self::assertSame(
            ['Reached'],
            $found->get('cn')?->getValues(),
        );
        self::assertSame(
            ['Reached'],
            $found->get('sn')?->getValues(),
        );

        $this->ldapClient()->delete('cn=Reached,dc=foo,dc=bar');
    }

    public function testAFilterNamingAnAttributeByAnAliasMatchesItsValues(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('surname', 'Smith'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            array_map(
                static fn(Entry $entry): string => $entry->getDn()->toString(),
                $entries->toArray(),
            ),
        );
    }

    public function testASearchBaseSpelledWithAnAliasFindsTheEntry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('commonName=alice,ou=people,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            array_map(
                static fn(Entry $entry): string => $entry->getDn()->toString(),
                $entries->toArray(),
            ),
        );
    }

    public function testCompareReachesAnEntryThroughANumericOidSpelledDn(): void
    {
        $this->authenticateUser();

        self::assertTrue($this->ldapClient()->compare(
            '2.5.4.3=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith',
        ));
    }

    public function testABindNameSpelledWithAnAliasAuthenticatesTheEntry(): void
    {
        $this->expectNotToPerformAssertions();

        $this->ldapClient()->bind(
            'commonName=user,dc=foo,dc=bar',
            '12345',
        );
    }
}
