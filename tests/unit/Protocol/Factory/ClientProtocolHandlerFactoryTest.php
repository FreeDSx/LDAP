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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientBasicHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientExtendedOperationHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientReferralHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSaslBindHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSearchHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientStartTlsHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSyncHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientUnbindHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientProtocolHandlerFactoryTest extends TestCase
{
    private ClientProtocolHandlerFactory $subject;

    private ClientQueue&MockObject $mockQueue;

    private RootDseLoader&MockObject $mockRootDseLoader;

    private ClientQueueInstantiator&MockObject $mockQueueInstantiator;

    private RequestInterface&MockObject $mockRequest;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);
        $this->mockRootDseLoader = $this->createMock(RootDseLoader::class);
        $this->mockQueueInstantiator = $this->createMock(ClientQueueInstantiator::class);
        $this->mockRequest = $this->createMock(RequestInterface::class);

        $this->mockQueueInstantiator
            ->method('make')
            ->willReturn($this->mockQueue);

        $this->subject = new ClientProtocolHandlerFactory(
            new ClientOptions(),
            $this->mockQueueInstantiator,
            $this->mockRootDseLoader
        );
    }

    public function test_it_should_get_a_search_response_handler(): void
    {
        self::assertInstanceOf(
            ClientSearchHandler::class,
            $this->subject->forResponse($this->mockRequest, new SearchResultEntry(new Entry('')))
        );
        self::assertInstanceOf(
            ClientSearchHandler::class,
            $this->subject->forResponse($this->mockRequest, new SearchResultDone(0))
        );
    }

    public function test_it_should_get_an_unbind_request_handler(): void
    {
        self::assertInstanceOf(
            ClientUnbindHandler::class,
            $this->subject->forRequest(Operations::unbind())
        );
    }

    public function test_it_should_get_a_basic_request_handler(): void
    {
        self::assertInstanceOf(
            ClientBasicHandler::class,
            $this->subject->forRequest(Operations::delete('cn=foo'))
        );
        self::assertInstanceOf(
            ClientBasicHandler::class,
            $this->subject->forRequest(Operations::bind('foo', 'bar')),
        );
        self::assertInstanceOf(
            ClientBasicHandler::class,
            $this->subject->forRequest(Operations::add(new Entry(''))),
        );
        self::assertInstanceOf(
            ClientBasicHandler::class,
            $this->subject->forRequest(Operations::modify(new Entry(''))),
        );
        self::assertInstanceOf(
            ClientBasicHandler::class,
            $this->subject->forRequest(Operations::move('cn=foo', 'cn=bar')),
        );
        self::assertInstanceOf(
            ClientBasicHandler::class,
            $this->subject->forRequest(Operations::cancel(1)),
        );
        self::assertInstanceOf(
            ClientBasicHandler::class,
            $this->subject->forRequest(Operations::whoami()),
        );
    }

    public function test_it_should_get_a_referral_handler(): void
    {
        self::assertInstanceOf(
            ClientReferralHandler::class,
            $this->subject->forResponse(
                $this->mockRequest,
                new DeleteResponse(ResultCode::REFERRAL)
            )
        );
    }

    public function test_it_should_get_an_extended_response_handler(): void
    {
        self::assertInstanceOf(
            ClientExtendedOperationHandler::class,
            $this->subject->forResponse(
                $this->mockRequest,
                new ExtendedResponse(new LdapResult(0), 'foo'))
        );
    }

    public function test_it_should_get_a_start_tls_handler(): void
    {
        self::assertInstanceOf(
            ClientStartTlsHandler::class,
            $this->subject->forResponse(
                new ExtendedRequest(ExtendedRequest::OID_START_TLS),
                new ExtendedResponse(
                    new LdapResult(0),
                    ExtendedRequest::OID_START_TLS
                )
            )
        );
    }

    public function test_it_should_get_a_basic_response_handler(): void
    {
        self::assertInstanceOf(
            ClientBasicHandler::class,
            $this->subject->forResponse(
                $this->mockRequest,
                new BindResponse(new LdapResult(0))
            )
        );
    }

    public function test_it_should_get_a_sasl_bind_handler(): void
    {
        self::assertInstanceOf(
            ClientSaslBindHandler::class,
            $this->subject->forRequest(new SaslBindRequest('DIGEST-MD5'))
        );
    }

    public function test_it_should_get_a_sync_handler_for_a_request(): void
    {
        self::assertInstanceOf(
            ClientSyncHandler::class,
            $this->subject->forRequest(new SyncRequest())
        );
    }

    public function test_it_should_get_a_sync_handler_for_a_response(): void
    {
        self::assertInstanceOf(
            ClientSyncHandler::class,
            $this->subject->forResponse(
                new SyncRequest(),
                new SyncRefreshDelete()
            ),
        );
    }

    public function test_it_should_get_a_sync_handler_for_an_sync_info_response(): void
    {
        self::assertInstanceOf(
            ClientSyncHandler::class,
            $this->subject->forResponse(
                new SyncRequest(),
                new SyncRefreshDelete(),
            ),
        );
    }
}
