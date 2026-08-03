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

namespace Tests\Integration\FreeDSx\Ldap\Controls;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end coverage for the Assertion (RFC 4528), Pre-Read / Post-Read (RFC 4527), and Tree-Delete controls.
 */
final class ServerControlsTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            [],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function test_assertion_allows_a_modify_when_it_matches(): void
    {
        $this->authenticateAdmin();
        $dn = $this->createPerson('assert-ok');

        $this->ldapClient()->send(
            Operations::modify($dn, Change::replace('sn', 'Jones')),
            Controls::assertion(Filters::equal('sn', 'Smith')),
        );

        self::assertSame('Jones', $this->readValue($dn, 'sn'));
    }

    public function test_assertion_fails_a_modify_when_it_does_not_match(): void
    {
        $this->authenticateAdmin();
        $dn = $this->createPerson('assert-no');

        try {
            $this->ldapClient()->send(
                Operations::modify($dn, Change::replace('sn', 'Jones')),
                Controls::assertion(Filters::equal('sn', 'Nope')),
            );
            self::fail('Expected an OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(ResultCode::ASSERTION_FAILED, $e->getCode());
        }

        self::assertSame('Smith', $this->readValue($dn, 'sn'));
    }

    public function test_assertion_allows_a_search_when_it_matches(): void
    {
        $this->bind();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
            Controls::assertion(Filters::equal('dc', 'foo')),
        );

        self::assertGreaterThan(0, $entries->count());
    }

    public function test_assertion_fails_a_search_when_it_does_not_match(): void
    {
        $this->bind();

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
                Controls::assertion(Filters::equal('dc', 'nope')),
            );
            self::fail('Expected an OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(ResultCode::ASSERTION_FAILED, $e->getCode());
        }

        # The connection survives the per-operation rejection: a follow-up search still succeeds.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
        );
        self::assertGreaterThan(0, $entries->count());
    }

    public function test_pre_read_and_post_read_capture_state_around_a_modify(): void
    {
        $this->authenticateAdmin();
        $dn = $this->createPerson('prepost');

        $response = $this->ldapClient()->send(
            Operations::modify($dn, Change::replace('sn', 'Jones')),
            Controls::preRead('sn'),
            Controls::postRead('sn'),
        );

        $preRead = $response?->controls()->get(Control::OID_PRE_READ);
        $postRead = $response?->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(PreReadResponseControl::class, $preRead);
        self::assertInstanceOf(PostReadResponseControl::class, $postRead);
        self::assertSame(['Smith'], $preRead->getEntry()->get('sn')?->getValues());
        self::assertSame(['Jones'], $postRead->getEntry()->get('sn')?->getValues());
    }

    public function test_pre_read_returns_the_entry_on_delete(): void
    {
        $this->authenticateAdmin();
        $dn = $this->createPerson('del-preread');

        $response = $this->ldapClient()->send(
            Operations::delete($dn),
            Controls::preRead('cn'),
        );

        $preRead = $response?->controls()->get(Control::OID_PRE_READ);
        self::assertInstanceOf(PreReadResponseControl::class, $preRead);
        self::assertSame(['del-preread'], $preRead->getEntry()->get('cn')?->getValues());
    }

    public function test_post_read_returns_the_entry_on_add(): void
    {
        $this->authenticateAdmin();
        $dn = 'cn=add-postread,ou=people,dc=foo,dc=bar';

        $response = $this->ldapClient()->send(
            Operations::add($this->person($dn, 'add-postread')),
            Controls::postRead('cn'),
        );

        $postRead = $response?->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(PostReadResponseControl::class, $postRead);
        self::assertSame(['add-postread'], $postRead->getEntry()->get('cn')?->getValues());
    }

    public function test_pre_read_withholds_an_attribute_the_identity_may_not_read(): void
    {
        $this->authenticateAdmin();

        $response = $this->ldapClient()->send(
            Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::replace(
                    'sn',
                    'Read-Policy',
                ),
            ),
            Controls::preRead(),
        );

        $preRead = $response?->controls()->get(Control::OID_PRE_READ);
        self::assertInstanceOf(
            PreReadResponseControl::class,
            $preRead,
        );
        self::assertNull($preRead->getEntry()->get('userPassword'));
        self::assertSame(
            ['user'],
            $preRead->getEntry()->get('cn')?->getValues(),
        );
    }

    public function test_post_read_cannot_name_an_attribute_the_identity_may_not_read(): void
    {
        $this->authenticateAdmin();

        $response = $this->ldapClient()->send(
            Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::replace(
                    'sn',
                    'Read-Policy-Named',
                ),
            ),
            Controls::postRead('userPassword'),
        );

        $postRead = $response?->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(
            PostReadResponseControl::class,
            $postRead,
        );
        self::assertSame(
            [],
            $postRead->getEntry()->getAttributes(),
        );
    }

    public function test_post_read_on_add_withholds_the_password_just_written(): void
    {
        $this->authenticateAdmin();
        $entry = $this->person(
            'cn=add-secret,ou=people,dc=foo,dc=bar',
            'add-secret',
        );
        $entry->set(
            'userPassword',
            '{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ=',
        );

        $response = $this->ldapClient()->send(
            Operations::add($entry),
            Controls::postRead(),
        );

        $postRead = $response?->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(
            PostReadResponseControl::class,
            $postRead,
        );
        self::assertNull($postRead->getEntry()->get('userPassword'));
        self::assertSame(
            ['add-secret'],
            $postRead->getEntry()->get('cn')?->getValues(),
        );
    }

    public function test_subtree_delete_removes_the_whole_subtree(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray('ou=del-tree,dc=foo,dc=bar', [
            'objectClass' => ['organizationalUnit'],
            'ou' => ['del-tree'],
        ]));
        $this->ldapClient()->create($this->person('cn=c1,ou=del-tree,dc=foo,dc=bar', 'c1'));
        $this->ldapClient()->create($this->person('cn=c2,ou=del-tree,dc=foo,dc=bar', 'c2'));

        $this->ldapClient()->send(
            Operations::delete('ou=del-tree,dc=foo,dc=bar'),
            Controls::subtreeDelete(),
        );

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        $dns = array_map(
            static fn(Entry $entry): string => (string) $entry->getDn(),
            iterator_to_array($entries),
        );
        self::assertNotContains('ou=del-tree,dc=foo,dc=bar', $dns);
        self::assertNotContains('cn=c1,ou=del-tree,dc=foo,dc=bar', $dns);
        self::assertNotContains('cn=c2,ou=del-tree,dc=foo,dc=bar', $dns);
    }

    public function test_deleting_a_non_leaf_without_the_control_is_rejected(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray('ou=non-leaf,dc=foo,dc=bar', [
            'objectClass' => ['organizationalUnit'],
            'ou' => ['non-leaf'],
        ]));
        $this->ldapClient()->create($this->person('cn=child,ou=non-leaf,dc=foo,dc=bar', 'child'));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        $this->ldapClient()->send(Operations::delete('ou=non-leaf,dc=foo,dc=bar'));
    }

    private function bind(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');
    }

    private function createPerson(string $cn): string
    {
        $dn = "cn={$cn},ou=people,dc=foo,dc=bar";
        $this->ldapClient()->create($this->person($dn, $cn));

        return $dn;
    }

    private function person(
        string $dn,
        string $cn,
    ): Entry {
        return Entry::fromArray($dn, [
            'objectClass' => ['inetOrgPerson', 'extensibleObject'],
            'cn' => [$cn],
            'sn' => ['Smith'],
        ]);
    }

    private function readValue(
        string $dn,
        string $attribute,
    ): ?string {
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base($dn)
                ->useBaseScope(),
        );

        return $entries->first()?->get($attribute)?->firstValue();
    }
}
