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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSearchHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerSearchHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ServerSearchHandler::class);
    }

    function it_should_send_a_search_request_to_the_request_handler(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar')
        );

        $entries = new Entries(Entry::create('dc=foo,dc=bar', ['cn' => 'foo']), Entry::create('dc=bar,dc=foo', ['cn' => 'bar']));
        $resultEntry1 = new LdapMessageResponse(2, new SearchResultEntry(Entry::create('dc=foo,dc=bar', ['cn' => 'foo'])));
        $resultEntry2 = new LdapMessageResponse(2, new SearchResultEntry(Entry::create('dc=bar,dc=foo', ['cn' => 'bar'])));

        $handler->search(Argument::any(), $search->getRequest())
            ->shouldBeCalled()
            ->willReturn($entries);

        $queue->sendMessage(
            $resultEntry1,
            $resultEntry2,
            new LdapMessageResponse(2, new SearchResultDone(0))
        )->shouldBeCalled();

        $this->handleRequest($search, $token, $handler, $queue, []);
    }
}
