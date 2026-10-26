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

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * The assertion control (RFC 4528), which lets an operation run only when its target entry matches the filter.
 */
trait AssertionControlTestsTrait
{
    public function testAnAssertionMatchingTheSearchBaseLetsTheSearchRun(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
            Controls::assertion(Filters::equal('dc', 'foo')),
        );

        self::assertGreaterThan(
            0,
            $entries->count(),
        );
    }

    public function testAnAssertionNotMatchingTheSearchBaseFailsTheSearch(): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
                Controls::assertion(Filters::equal('dc', 'nope')),
            );
            self::fail('Expected an OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
        }

        // The rejection ends only the operation, not the connection.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
        );
        self::assertGreaterThan(
            0,
            $entries->count(),
        );
    }

    public function testAnAssertionMatchingTheEntryLetsTheCompareAnswer(): void
    {
        $this->authenticateUser();

        self::assertTrue($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith',
            Controls::assertion(Filters::equal('cn', 'alice')),
        ));
    }

    public function testAnAssertionNotMatchingTheEntryFailsTheCompare(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith',
            Controls::assertion(Filters::equal('cn', 'nobody')),
        );
    }

    public function testACompareOfAMissingEntryAnswersBeforeItsAssertion(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->ldapClient()->compare(
            'cn=nobody,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith',
            Controls::assertion(Filters::equal('cn', 'nobody')),
        );
    }

    public function testAnAssertionMatchingTheAddedEntryLetsTheAddRun(): void
    {
        $this->authenticateAdmin();
        $entry = $this->assertionTarget('assert-add-ok');

        $this->ldapClient()->send(
            Operations::add($entry),
            Controls::assertion(Filters::equal('sn', 'Smith')),
        );
        $this->authenticateUser();
        $added = $this->ldapClient()->read($entry->getDn()->toString());
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete($entry->getDn()->toString()));

        self::assertSame(
            ['Smith'],
            $added?->get('sn')?->getValues(),
        );
    }

    public function testAnAssertionNotMatchingTheAddedEntryFailsTheAdd(): void
    {
        $this->authenticateAdmin();
        $entry = $this->assertionTarget('assert-add-no');

        try {
            $this->ldapClient()->send(
                Operations::add($entry),
                Controls::assertion(Filters::equal('sn', 'doesnotmatch')),
            );
            self::fail('Expected an OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
        }
        $this->authenticateUser();

        self::assertNull($this->ldapClient()->read($entry->getDn()->toString()));
    }

    public function testAnAssertionMatchingTheEntryLetsTheModifyRun(): void
    {
        $this->authenticateAdmin();
        $dn = $this->createAssertionTarget('assert-modify-ok');

        $this->ldapClient()->send(
            Operations::modify(
                $dn,
                Change::replace('sn', 'Jones'),
            ),
            Controls::assertion(Filters::equal('sn', 'Smith')),
        );
        $this->authenticateUser();
        $modified = $this->ldapClient()->read($dn);
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete($dn));

        self::assertSame(
            ['Jones'],
            $modified?->get('sn')?->getValues(),
        );
    }

    public function testAnAssertionNotMatchingTheEntryFailsTheModify(): void
    {
        $this->authenticateAdmin();
        $dn = $this->createAssertionTarget('assert-modify-no');

        try {
            $this->ldapClient()->send(
                Operations::modify(
                    $dn,
                    Change::replace('sn', 'Jones'),
                ),
                Controls::assertion(Filters::equal('sn', 'Nope')),
            );
            self::fail('Expected an OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
        }
        $this->authenticateUser();
        $unchanged = $this->ldapClient()->read($dn);
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete($dn));

        self::assertSame(
            ['Smith'],
            $unchanged?->get('sn')?->getValues(),
        );
    }

    public function testAnAssertionNotMatchingTheEntryFailsTheDelete(): void
    {
        $this->authenticateAdmin();
        $dn = $this->createAssertionTarget('assert-delete-no');

        try {
            $this->ldapClient()->send(
                Operations::delete($dn),
                Controls::assertion(Filters::equal('sn', 'Nope')),
            );
            self::fail('Expected an OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
        }
        $this->authenticateUser();
        $kept = $this->ldapClient()->read($dn);
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete($dn));

        self::assertNotNull($kept);
    }

    public function testAnAssertionNotMatchingTheBaseFailsTheSubtreeDelete(): void
    {
        $this->authenticateAdmin();
        $this->createAssertionSubtree('assert-tree-no');

        try {
            $this->ldapClient()->send(
                Operations::delete('ou=assert-tree-no,dc=foo,dc=bar'),
                Controls::subtreeDelete(),
                Controls::assertion(Filters::equal('ou', 'nope')),
            );
            self::fail('Expected an OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
        }
        $this->authenticateUser();
        $kept = $this->ldapClient()->read('cn=child,ou=assert-tree-no,dc=foo,dc=bar');
        $this->asAdmin(fn(LdapClient $admin) => $admin->send(
            Operations::delete('ou=assert-tree-no,dc=foo,dc=bar'),
            Controls::subtreeDelete(),
        ));

        self::assertNotNull($kept);
    }

    public function testAnAssertionMatchingTheBaseLetsTheSubtreeDeleteRun(): void
    {
        $this->authenticateAdmin();
        $this->createAssertionSubtree('assert-tree-yes');

        $this->ldapClient()->send(
            Operations::delete('ou=assert-tree-yes,dc=foo,dc=bar'),
            Controls::subtreeDelete(),
            Controls::assertion(Filters::equal('ou', 'assert-tree-yes')),
        );
        $this->authenticateUser();

        self::assertNull($this->ldapClient()->read('ou=assert-tree-yes,dc=foo,dc=bar'));
        self::assertNull($this->ldapClient()->read('cn=child,ou=assert-tree-yes,dc=foo,dc=bar'));
    }

    public function testAnAssertionNotMatchingTheEntryFailsTheModifyDn(): void
    {
        $this->authenticateAdmin();
        $dn = $this->createAssertionTarget('assert-rename-no');

        try {
            $this->ldapClient()->send(
                Operations::rename(
                    $dn,
                    'cn=assert-renamed',
                ),
                Controls::assertion(Filters::equal('sn', 'Nope')),
            );
            self::fail('Expected an OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
        }
        $this->authenticateUser();
        $kept = $this->ldapClient()->read($dn);
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete($dn));

        self::assertNotNull($kept);
        self::assertNull($this->ldapClient()->read('cn=assert-renamed,ou=people,dc=foo,dc=bar'));
    }

    /**
     * An entry under ou=people for a write carrying an assertion to act on.
     */
    private function assertionTarget(string $cn): Entry
    {
        return Entry::fromArray(
            "cn={$cn},ou=people,dc=foo,dc=bar",
            [
                'objectClass' => ['inetOrgPerson'],
                'cn' => [$cn],
                'sn' => ['Smith'],
            ],
        );
    }

    /**
     * Creates the entry a write carrying an assertion acts on, which the test removes again.
     */
    private function createAssertionTarget(string $cn): string
    {
        $entry = $this->assertionTarget($cn);
        $this->ldapClient()->create($entry);

        return $entry->getDn()->toString();
    }

    private function createAssertionSubtree(string $ou): void
    {
        $this->ldapClient()->create(Entry::fromArray(
            "ou={$ou},dc=foo,dc=bar",
            [
                'objectClass' => ['organizationalUnit'],
                'ou' => [$ou],
            ],
        ));
        $this->ldapClient()->create(Entry::fromArray(
            "cn=child,ou={$ou},dc=foo,dc=bar",
            [
                'objectClass' => ['inetOrgPerson'],
                'cn' => ['child'],
                'sn' => ['Smith'],
            ],
        ));
    }
}
