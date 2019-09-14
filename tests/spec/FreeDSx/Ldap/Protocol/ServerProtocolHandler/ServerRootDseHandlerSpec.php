<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerRootDseHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PhpSpec\ObjectBehavior;

class ServerRootDseHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ServerRootDseHandler::class);
    }

    function it_should_send_back_a_RootDSE(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope()
        );

        $queue->sendMessage(
            new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
                'namingContexts' => 'dc=Foo,dc=Bar',
                'supportedExtension' => [
                    ExtendedRequest::OID_WHOAMI,
                ],
                'supportedLDAPVersion' => ['3'],
                'vendorName' => 'Foo',
            ]))),
            new LdapMessageResponse(1, new SearchResultDone(0))
        )->shouldBeCalled();

        $this->handleRequest(
            $search,
            $token,
            $handler,
            $queue,
            ['dse_vendor_name' => 'Foo', 'dse_naming_contexts' => ['dc=Foo,dc=Bar']]
        );
    }

    function it_should_only_return_attribute_names_from_the_RootDSE_if_requested(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('')
                ->useBaseScope()
                ->setAttributesOnly(true)
        );

        $queue->sendMessage(
            new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
                'namingContexts' => [],
                'supportedExtension' => [],
                'supportedLDAPVersion' => [],
                'vendorName' => [],
            ]))),
            new LdapMessageResponse(1, new SearchResultDone(0))
        )->shouldBeCalled();

        $this->handleRequest(
            $search,
            $token,
            $handler,
            $queue,
            ['dse_vendor_name' => 'Foo', 'dse_naming_contexts' => ['dc=Foo,dc=Bar']]
        );
    }

    function it_should_only_return_specific_attributes_from_the_RootDSE_if_requested(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('')
                ->useBaseScope()
                ->setAttributes('namingcontexts')
        );

        # The reset below is needed, unfortunately, to properly spec due to how the objects change...
        $entry = Entry::create('', ['namingContexts' => 'dc=Foo,dc=Bar',]);
        $entry->changes()->reset();
        $entry->get('namingContexts')->equals(new Attribute('foo'));

        $queue->sendMessage(
            new LdapMessageResponse(
                1,
                new SearchResultEntry($entry)
            ),
            new LdapMessageResponse(1, new SearchResultDone(0))
        )->shouldBeCalled();

        $this->handleRequest(
            $search,
            $token,
            $handler,
            $queue,
            ['dse_vendor_name' => 'Foo', 'dse_naming_contexts' => ['dc=Foo,dc=Bar']]
        );
    }
}
