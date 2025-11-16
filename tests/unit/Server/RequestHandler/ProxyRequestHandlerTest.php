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

namespace Tests\Unit\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ProxyRequestHandlerTest extends TestCase
{
    private ProxyRequestHandler $subject;

    private LdapClient&MockObject $mockClient;

    private RequestContext&MockObject $mockContext;

    protected function setUp(): void
    {
        $this->mockClient = $this->createMock(LdapClient::class);
        $this->mockContext = $this->createMock(RequestContext::class);

        $this->mockContext
            ->method('controls')
            ->willReturn(new ControlBag());

        $this->mockContext
            ->method('token')
            ->willReturn(new BindToken('foo', 'bar'));

        $this->subject = new ProxyRequestHandler(new ClientOptions());
        $this->subject->setLdapClient($this->mockClient);;
    }

    public function test_it_should_send_an_add_request(): void
    {
        $add = Operations::add(Entry::create('cn=foo,dc=freedsx,dc=local'));

        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with($add);

        $this->subject->add(
            $this->mockContext,
            $add,
        );
    }

    public function test_it_should_send_a_delete_request(): void
    {
        $delete = Operations::delete('cn=foo,dc=freedsx,dc=local');

        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with($delete);

        $this->subject->delete(
            $this->mockContext,
            $delete
        );
    }

    public function test_it_should_send_a_modify_request(): void
    {
        $modify = Operations::modify('cn=foo,dc=freedsx,dc=local', Change::add('foo', 'bar'));

        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with($modify);

        $this->subject->modify(
            $this->mockContext,
            $modify,
        );
    }

    public function test_it_should_send_a_modify_dn_request(): void
    {
        $modifyDn = Operations::rename('cn=foo,dc=freedsx,dc=local', 'cn=bar');

        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with($modifyDn);

        $this->subject->modifyDn(
            $this->mockContext,
            $modifyDn,
        );
    }

    public function test_it_should_send_a_search_request(): void
    {
        $search = Operations::search(
            Filters::present('objectClass'),
            'cn'
        )->base('dc=foo');
        $entries = new Entries(Entry::create('dc=foo'));

        $this->mockClient
            ->expects($this->once())
            ->method('search')
            ->willReturn($entries);

        self::assertEquals(
            $entries,
            $this->subject->search($this->mockContext, $search),
        );
    }

    public function test_it_should_send_a_compare_request_and_return_false_on_no_match(): void
    {
        $compare = Operations::compare('foo', 'foo', 'bar');

        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with($compare)
            ->willReturn(new LdapMessageResponse(
                1,
                new CompareResponse(ResultCode::COMPARE_FALSE)
            ));

        self::assertFalse(
            $this->subject->compare(
                $this->mockContext,
                $compare
            )
        );
    }

    public function test_it_should_send_a_compare_request_and_return_true_on_match(): void
    {
        $compare = Operations::compare('foo', 'foo', 'bar');

        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with($compare)
            ->willReturn(new LdapMessageResponse(
                1,
                new CompareResponse(ResultCode::COMPARE_TRUE)
            ));

        self::assertTrue(
            $this->subject->compare(
                $this->mockContext,
                $compare,
            )
        );
    }

    public function test_it_should_send_an_extended_request(): void
    {
        $extended = Operations::extended('foo', 'bar');

        $this->mockClient
            ->expects($this->once())
            ->method('send')
            ->with($extended);

        $this->subject->extended(
            $this->mockContext,
            $extended,
        );
    }

    public function test_it_should_handle_a_bind_request(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('bind')
            ->willReturn(new LdapMessageResponse(
                1,
                new BindResponse(new LdapResult(0)),
            ));

        self::assertTrue($this->subject->bind(
            'foo',
            'bar'
        ));
    }

    public function test_it_should_handle_a_bind_request_failure(): void
    {
        self::expectException(OperationException::class);

        $this->mockClient
            ->expects($this->once())
            ->method('bind')
            ->willThrowException(new BindException('Foo!', 49));

        $this->subject->bind(
            'foo',
            'bar',
        );
    }
}
