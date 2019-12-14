<?php
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
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filters;
use PhpSpec\ObjectBehavior;

class OperationsSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(Operations::class);
    }

    function it_should_create_a_sasl_bind()
    {
        $this::bindSasl(['username' => 'foo', 'password' => 'bar'])->shouldBeLike(
            new SaslBindRequest('', null, ['username' => 'foo', 'password' => 'bar'])
        );
        $this::bindSasl(['username' => 'foo', 'password' => 'bar'], 'DIGEST-MD5')->shouldBeLike(
            new SaslBindRequest('DIGEST-MD5', null, ['username' => 'foo', 'password' => 'bar'])
        );
    }

    function it_should_create_an_add_operation()
    {
        $this::add(new Entry('foo'))->shouldBeLike(new AddRequest(new Entry('foo')));
    }

    function it_should_create_a_modify_operation()
    {
        $this::modify('foo', Change::replace('foo', 'bar'))->shouldBeLike(new ModifyRequest('foo', Change::replace('foo', 'bar')));
    }

    function it_should_create_a_rename_operation()
    {
        $this::rename('cn=foo,dc=bar,dc=foo', 'foo=bar')->shouldBeLike(new ModifyDnRequest('cn=foo,dc=bar,dc=foo', 'foo=bar', true));
    }

    function it_should_create_a_move_operation()
    {
        // Calling getRdn triggers a cache of RDN pieces on the object. Need this for the check..
        $dn = new Dn('cn=foo,dc=example,dc=local');
        $dn->getRdn();

        $this::move(new Dn('cn=foo,dc=example,dc=local'), new Dn('ou=foo,dc=example,dc=local'))->shouldBeLike(
            new ModifyDnRequest('cn=foo,dc=example,dc=local', 'cn=foo', true, 'ou=foo,dc=example,dc=local')
        );
    }

    function it_should_create_a_delete_operation()
    {
        $this::delete('cn=foo,dc=example,dc=local')->shouldBeLike(new DeleteRequest('cn=foo,dc=example,dc=local'));
    }

    function it_should_create_a_search_operation()
    {
        $this::search(new EqualityFilter('foo', 'bar'), 'cn')->shouldBeLike(new SearchRequest(new EqualityFilter('foo','bar'), 'cn'));
    }

    function it_should_create_a_compare_operation()
    {
        $this::compare('cn=foo,dc=example,dc=local', 'foo', 'bar')->shouldBeLike(new CompareRequest('cn=foo,dc=example,dc=local', new EqualityFilter('foo', 'bar')));
    }

    function it_should_create_an_unbind_operation()
    {
        $this::unbind()->shouldBeLike(new UnbindRequest());
    }

    function it_should_create_an_anonymous_bind_operation()
    {
        $this::bindAnonymously()->shouldBeLike(new AnonBindRequest());
    }

    function it_should_create_a_username_password_bind_operation()
    {
        $this::bind('foo', 'bar')->shouldBeLike(new SimpleBindRequest('foo', 'bar'));
    }

    function it_should_create_an_abandon_request()
    {
        $this::abandon(9)->shouldBeLike(new AbandonRequest(9));
    }

    function it_should_create_a_whoami_request()
    {
        $this::whoami()->shouldBeLike(new ExtendedRequest(ExtendedRequest::OID_WHOAMI));
    }

    function it_should_create_a_cancel_request()
    {
        $this->cancel(1)->shouldBeLike(new CancelRequest(1));
    }

    function it_should_create_a_base_object_search()
    {
        $this::read('dc=foo,dc=bar')->shouldBeLike(
            (new SearchRequest(Filters::present('objectClass')))->useBaseScope()->base('dc=foo,dc=bar')
        );

        $this::read('dc=foo,dc=bar', 'foo', 'bar')->shouldBeLike(
            (new SearchRequest(Filters::present('objectClass')))
                ->useBaseScope()
                ->base('dc=foo,dc=bar')
                ->select('foo', 'bar')
        );
    }

    function it_should_create_a_single_level_search()
    {
        $this::list(Filters::equal('foo', 'bar'), 'dc=foo,dc=bar', 'cn')->shouldBeLike(
            (new SearchRequest(Filters::equal('foo', 'bar', 'cn'), 'cn'))->base('dc=foo,dc=bar')->useSingleLevelScope()
        );
    }

    function it_should_create_a_password_modify_request()
    {
        $this::passwordModify('foo', '12345', '6789')->shouldBeLike(new PasswordModifyRequest('foo', '12345', '6789'));
    }
}
