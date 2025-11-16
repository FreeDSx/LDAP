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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

class OperationsTest extends TestCase
{
    public function test_it_should_create_a_sasl_bind(): void
    {
        self::assertEquals(
            new SaslBindRequest(
                '',
                null,
                [
                    'username' => 'foo',
                    'password' => 'bar'
                ]
            ),
            Operations::bindSasl([
                'username' => 'foo',
                'password' => 'bar',
            ])
        );

        self::assertEquals(
            new SaslBindRequest(
                'DIGEST-MD5',
                null,
                [
                    'username' => 'foo',
                    'password' => 'bar',
                ]
            ),
            Operations::bindSasl(
                [
                    'username' => 'foo',
                    'password' => 'bar',
                ],
                'DIGEST-MD5'
            )
        );
    }

    public function test_it_should_create_an_add_operation(): void
    {
        self::assertEquals(
            new AddRequest(new Entry('foo')),
            Operations::add(new Entry('foo')),
        );
    }

    public function test_it_should_create_a_modify_operation(): void
    {
        self::assertEquals(
            new ModifyRequest(
                'foo',
                Change::replace(
                    'foo',
                    'bar',
                ),
            ),
            Operations::modify(
                'foo',
                Change::replace(
                    'foo',
                    'bar'
                )
            )
        );
    }

    public function test_it_should_create_a_rename_operation(): void
    {
        self::assertEquals(
            new ModifyDnRequest(
                'cn=foo,dc=bar,dc=foo',
                'foo=bar',
                true
            ),
            Operations::rename(
                'cn=foo,dc=bar,dc=foo',
                'foo=bar',
            ),
        );
    }

    public function test_it_should_create_a_move_operation(): void
    {
        // Calling getRdn triggers a cache of RDN pieces on the object. Need this for the check..
        $dn = new Dn('cn=foo,dc=example,dc=local');
        $dn->getRdn();

        self::assertEquals(
            new ModifyDnRequest(
                'cn=foo,dc=example,dc=local',
                'cn=foo',
                true,
                'ou=foo,dc=example,dc=local'
            ),
            Operations::move(
                new Dn('cn=foo,dc=example,dc=local'),
                new Dn('ou=foo,dc=example,dc=local'),
            ),
        );
    }

    public function test_it_should_create_a_delete_operation(): void
    {
        self::assertEquals(
            new DeleteRequest('cn=foo,dc=example,dc=local'),
            Operations::delete('cn=foo,dc=example,dc=local'),
        );
    }

    public function test_it_should_create_a_search_operation(): void
    {
        self::assertEquals(
            new SearchRequest(
                Filters::equal(
                    'foo',
                    'bar'
                ),
                'cn',
            ),
            Operations::search(
                new EqualityFilter(
                    'foo',
                    'bar'
                ),
                'cn',
            )
        );
    }

    public function test_it_should_create_a_compare_operation(): void
    {
        self::assertEquals(
            new CompareRequest(
                'cn=foo,dc=example,dc=local',
                new EqualityFilter(
                    'foo',
                    'bar',
                )
            ),
            Operations::compare(
                'cn=foo,dc=example,dc=local',
                'foo',
                'bar',
            ),
        );
    }

    public function test_it_should_create_an_unbind_operation(): void
    {
        self::assertEquals(
            new UnbindRequest(),
            Operations::unbind(),
        );
    }

    public function test_it_should_create_an_anonymous_bind_operation(): void
    {
        self::assertEquals(
            new AnonBindRequest(),
            Operations::bindAnonymously(),
        );
    }

    public function test_it_should_create_a_username_password_bind_operation(): void
    {
        self::assertEquals(
            new SimpleBindRequest(
                'foo',
                'bar',
            ),
            Operations::bind(
                'foo',
                'bar',
            ),
        );
    }

    public function test_it_should_create_an_abandon_request(): void
    {
        self::assertEquals(
            new AbandonRequest(9),
            Operations::abandon(9),
        );
    }

    public function test_it_should_create_a_whoami_request(): void
    {
        self::assertEquals(
            new ExtendedRequest(ExtendedRequest::OID_WHOAMI),
            Operations::whoami(),
        );
    }

    public function test_it_should_create_a_cancel_request(): void
    {
        self::assertEquals(
            new CancelRequest(1),
            Operations::cancel(1),
        );
    }

    public function test_it_should_create_a_base_object_search(): void
    {
        self::assertEquals(
            (new SearchRequest(Filters::present('objectClass')))
                ->useBaseScope()
                ->base('dc=foo,dc=bar'),
            Operations::read('dc=foo,dc=bar'),
        );

        self::assertEquals(
            (new SearchRequest(Filters::present('objectClass')))
                ->useBaseScope()
                ->base('dc=foo,dc=bar')
                ->select('foo', 'bar'),
            Operations::read('dc=foo,dc=bar', 'foo', 'bar'),
        );
    }

    public function test_it_should_create_a_single_level_search(): void
    {
        self::assertEquals(
            (new SearchRequest(Filters::equal('foo', 'bar'), 'cn'))
                ->base('dc=foo,dc=bar')
                ->useSingleLevelScope(),
            Operations::list(
                Filters::equal(
                    'foo',
                    'bar'
                ),
                'dc=foo,dc=bar',
                'cn'
            ),
        );
    }

    public function test_it_should_create_a_password_modify_request(): void
    {
        self::assertEquals(
            new PasswordModifyRequest(
                'foo',
                '12345',
                '6789',
            ),
            Operations::passwordModify(
                'foo',
                '12345',
                '6789',
            )
        );
    }
}
