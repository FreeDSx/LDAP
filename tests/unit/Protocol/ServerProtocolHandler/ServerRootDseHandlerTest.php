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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\Control;
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
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerRootDseHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private ServerRootDseHandler $subject;

    private TokenInterface&MockObject $mockToken;

    private ServerOptions $options;

    private PagingHandlerInterface&MockObject $mockPagingHandler;

    private RootDseHandlerInterface&MockObject $mockDseHandler;

    protected function setUp(): void
    {
        $this->options = new ServerOptions();
        $this->mockPagingHandler = $this->createMock(PagingHandlerInterface::class);
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockDseHandler = $this->createMock(RootDseHandlerInterface::class);

        $this->subject = new ServerRootDseHandler(
            $this->options,
            $this->mockQueue,
            null,
        );
    }

    public function test_it_should_send_back_a_RootDSE(): void
    {
        $this->options
            ->setDseVendorName('Foo')
            ->setDseNamingContexts('dc=Foo,dc=Bar');

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope()
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::equalTo(new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
                    'namingContexts' => 'dc=Foo,dc=Bar',
                    'supportedExtension' => [
                        ExtendedRequest::OID_WHOAMI,
                    ],
                    'supportedLDAPVersion' => ['3'],
                    'vendorName' => 'Foo',
                ])))),
                self::equalTo(new LdapMessageResponse(1, new SearchResultDone(0)))
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_send_back_a_RootDSE_with_paging_support_if_the_paging_handler_is_set(): void
    {
        $this->options
            ->setDseVendorName('Foo')
            ->setDseNamingContexts('dc=Foo,dc=Bar')
            ->setPagingHandler($this->mockPagingHandler);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope()
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $search */
                    $search = $response->getResponse();
                    $entry = $search->getEntry();

                    return $entry->get('supportedControl')
                        ?->has(Control::OID_PAGING) ?? false;
                }),
                new LdapMessageResponse(1, new SearchResultDone(0)),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_send_a_request_to_the_dispatcher_if_it_implements_a_rootdse_aware_interface(): void
    {
        $this->options
            ->setDseVendorName('Foo')
            ->setDseNamingContexts('dc=Foo,dc=Bar');

        $this->subject = new ServerRootDseHandler(
            $this->options,
            $this->mockQueue,
            $this->mockDseHandler,
        );

        $searchReqeust = (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope();
        $search = new LdapMessageRequest(
            1,
            $searchReqeust
        );
        $rootDse = Entry::create('', [
            'namingContexts' => 'dc=Foo,dc=Bar',
            'supportedExtension' => [
                ExtendedRequest::OID_WHOAMI,
            ],
            'supportedLDAPVersion' => ['3'],
            'vendorName' => 'Foo',
        ]);

        $handlerRootDse = Entry::fromArray('', ['foo' => 'bar']);

        $this->mockDseHandler
            ->expects($this->once())
            ->method('rootDse')
            ->with(
                self::isInstanceOf(RequestContext::class),
                $searchReqeust,
                $rootDse,
            )
            ->willReturn($handlerRootDse);

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(1, new SearchResultEntry($handlerRootDse)),
                new LdapMessageResponse(1, new SearchResultDone(0))
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_include_supported_sasl_mechanisms_when_configured(): void
    {
        $this->options
            ->setSaslMechanisms(ServerOptions::SASL_PLAIN, ServerOptions::SASL_CRAM_MD5);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope()
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $search */
                    $search = $response->getResponse();
                    $attribute = $search->getEntry()->get('supportedSaslMechanisms');

                    return $attribute !== null
                        && $attribute->has(ServerOptions::SASL_PLAIN)
                        && $attribute->has(ServerOptions::SASL_CRAM_MD5);
                }),
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(0)
                ),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_only_return_attribute_names_from_the_RootDSE_if_requested(): void
    {
        $this->options
            ->setDseVendorName('Foo')
            ->setDseNamingContexts('dc=Foo,dc=Bar');

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('')
                ->useBaseScope()
                ->setAttributesOnly(true)
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
                    'namingContexts' => [],
                    'supportedExtension' => [],
                    'supportedLDAPVersion' => [],
                    'vendorName' => [],
                ]))),
                new LdapMessageResponse(1, new SearchResultDone(0))
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_only_return_specific_attributes_from_the_RootDSE_if_requested(): void
    {
        $this->options
            ->setDseVendorName('Foo')
            ->setDseNamingContexts('dc=Foo,dc=Bar');

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('')
                ->useBaseScope()
                ->setAttributes('namingcontexts')
        );

        # The reset below is needed, unfortunately, to properly test due to how the objects change...
        $entry = Entry::create('', ['namingContexts' => 'dc=Foo,dc=Bar', ]);
        $entry->changes()->reset();
        $entry->get('namingContexts')?->equals(new Attribute('foo'));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry($entry)
                ),
                new LdapMessageResponse(1, new SearchResultDone(0))
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }
}
