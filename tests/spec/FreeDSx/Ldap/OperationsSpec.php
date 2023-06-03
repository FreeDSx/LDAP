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

namespace spec\FreeDSx\Ldap;

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
use PhpSpec\ObjectBehavior;

class OperationsSpec extends ObjectBehavior
{
    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Operations::class);
    }

    public function it_should_create_a_sasl_bind(): void
    {
        $this::bindSasl([
            'username' => 'foo',
            'password' => 'bar',
        ])->shouldBeLike(new SaslBindRequest(
            '',
            null,
            [
                'username' => 'foo',
                'password' => 'bar'
            ]
        ));
        $this::bindSasl(
            [
                'username' => 'foo',
                'password' => 'bar',
            ],
            'DIGEST-MD5'
        )->shouldBeLike(
            new SaslBindRequest(
                'DIGEST-MD5',
                null,
                [
                'username' => 'foo',
                'password' => 'bar',
            ]
            )
        );
    }

    public function it_should_create_an_add_operation(): void
    {
        $this::add(new Entry('foo'))
            ->shouldBeLike(new AddRequest(new Entry('foo')));
    }

    public function it_should_create_a_modify_operation(): void
    {
        $this::modify(
            'foo',
            Change::replace(
                'foo',
                'bar'
            )
        )->shouldBeLike(new ModifyRequest(
            'foo',
            Change::replace(
                'foo',
                'bar'
            )
        ));
    }

    public function it_should_create_a_rename_operation(): void
    {
        $this::rename(
            'cn=foo,dc=bar,dc=foo',
            'foo=bar'
        )->shouldBeLike(new ModifyDnRequest(
            'cn=foo,dc=bar,dc=foo',
            'foo=bar',
            true
        ));
    }

    public function it_should_create_a_move_operation(): void
    {
        // Calling getRdn triggers a cache of RDN pieces on the object. Need this for the check..
        $dn = new Dn('cn=foo,dc=example,dc=local');
        $dn->getRdn();

        $this::move(
            new Dn('cn=foo,dc=example,dc=local'),
            new Dn('ou=foo,dc=example,dc=local')
        )->shouldBeLike(new ModifyDnRequest(
            'cn=foo,dc=example,dc=local',
            'cn=foo',
            true,
            'ou=foo,dc=example,dc=local'
        ));
    }

    public function it_should_create_a_delete_operation(): void
    {
        $this::delete('cn=foo,dc=example,dc=local')
            ->shouldBeLike(new DeleteRequest('cn=foo,dc=example,dc=local'));
    }

    public function it_should_create_a_search_operation(): void
    {
        $this::search(
            new EqualityFilter(
                'foo',
                'bar'
            ),
            'cn'
        )->shouldBeLike(new SearchRequest(
            new EqualityFilter(
                'foo',
                'bar'
            ),
            'cn'
        ));
    }

    public function it_should_create_a_compare_operation(): void
    {
        $this::compare(
            'cn=foo,dc=example,dc=local',
            'foo',
            'bar'
        )->shouldBeLike(new CompareRequest(
            'cn=foo,dc=example,dc=local',
            new EqualityFilter(
                'foo',
                'bar'
            )
        ));
    }

    public function it_should_create_an_unbind_operation(): void
    {
        $this::unbind()
            ->shouldBeLike(new UnbindRequest());
    }

    public function it_should_create_an_anonymous_bind_operation(): void
    {
        $this::bindAnonymously()
            ->shouldBeLike(new AnonBindRequest());
    }

    public function it_should_create_a_username_password_bind_operation(): void
    {
        $this::bind(
            'foo',
            'bar'
        )->shouldBeLike(new SimpleBindRequest(
            'foo',
            'bar'
        ));
    }

    public function it_should_create_an_abandon_request(): void
    {
        $this::abandon(9)
            ->shouldBeLike(new AbandonRequest(9));
    }

    public function it_should_create_a_whoami_request(): void
    {
        $this::whoami()
            ->shouldBeLike(new ExtendedRequest(ExtendedRequest::OID_WHOAMI));
    }

    public function it_should_create_a_cancel_request(): void
    {
        $this->cancel(1)
            ->shouldBeLike(new CancelRequest(1));
    }

    public function it_should_create_a_base_object_search(): void
    {
        $this::read('dc=foo,dc=bar')
            ->shouldBeLike(
                (new SearchRequest(Filters::present('objectClass')))
                    ->useBaseScope()
                    ->base('dc=foo,dc=bar')
            );

        $this::read('dc=foo,dc=bar', 'foo', 'bar')
            ->shouldBeLike(
                (new SearchRequest(Filters::present('objectClass')))
                    ->useBaseScope()
                    ->base('dc=foo,dc=bar')
                    ->select('foo', 'bar')
            );
    }

    public function it_should_create_a_single_level_search(): void
    {
        $this::list(
            Filters::equal(
                'foo',
                'bar'
            ),
            'dc=foo,dc=bar',
            'cn'
        )->shouldBeLike(
            (new SearchRequest(Filters::equal('foo', 'bar'), 'cn'))
                ->base('dc=foo,dc=bar')
                ->useSingleLevelScope()
        );
    }

    public function it_should_create_a_password_modify_request(): void
    {
        $this::passwordModify(
            'foo',
            '12345',
            '6789'
        )->shouldBeLike(new PasswordModifyRequest(
            'foo',
            '12345',
            '6789'
        ));
    }
}
