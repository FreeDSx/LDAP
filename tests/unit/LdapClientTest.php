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

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Search\DirSync;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Paging;
use FreeDSx\Ldap\Search\RangeRetrieval;
use FreeDSx\Ldap\Search\Vlv;
use FreeDSx\Ldap\Sync\SyncRepl;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class LdapClientTest extends TestCase
{
    use TestFactoryTrait;

    private ClientProtocolHandler&MockObject $mockHandler;

    private Container $container;

    private ClientQueueInstantiator&MockObject $mockQueueInstantiator;

    private LdapClient $subject;

    protected function setUp(): void {
        $this->mockHandler = $this->createMock(ClientProtocolHandler::class);
        $this->mockQueueInstantiator = $this->createMock(ClientQueueInstantiator::class);

        $this->mockQueueInstantiator
            ->method('isInstantiatedAndConnected')
            ->willReturn(false);

        $this->container = new Container(
            [
                ClientProtocolHandler::class => $this->mockHandler,
                ClientQueueInstantiator::class => $this->mockQueueInstantiator,
            ]
        );

        $this->subject = new LdapClient(
            new ClientOptions(),
            $this->container,
        );
    }

    public function test_it_should_send_a_message_and_throw_an_exception_if_no_response_is_received_on_sendAndReceive(): void
    {
        $this->expectException(OperationException::class);

        $this->mockHandler
            ->method('send')
            ->willReturn(null);

        $this->subject->sendAndReceive(Operations::read(''));
    }

    public function test_it_should_send_a_message_and_return_the_response_on_sendAndReceive(): void {
        $mockResponse = $this->createMock(LdapMessageResponse::class);

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->willReturn($mockResponse);

        self::assertSame(
            $mockResponse,
            $this->subject->sendAndReceive(Operations::read('')),
        );
    }

    public function test_it_should_send_a_search_and_get_entries_back(): void
    {
        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->willReturn(
                $this::makeSearchResponseFromEntries(new Entries(
                    Entry::create('dc=foo,dc=bar')
                ))
            );

        $search = Operations::search(Filters::equal(
            'foo',
            'bar'
        ));

        self::assertEquals(
            new Entries(Entry::create('dc=foo,dc=bar')),
            $this->subject->search($search),
        );
    }

    public function test_it_should_bind(): void
    {
        $response = new LdapMessageResponse(
            1,
            new BindResponse(new LdapResult(
                0,
                ''
            ))
        );

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(new SimpleBindRequest(
                'foo',
                'bar',
                3
            ))
            ->willReturn($response);

        self::assertEquals(
            $response,
            $this->subject->bind(
                'foo',
                'bar',
            )
        );
    }

    public function test_it_should_construct_a_pager_helper(): void
    {
        self::expectNotToPerformAssertions();

        $this->subject->paging(Operations::search(
            Filters::equal(
                'foo',
                'bar'
            ))
        );
    }

    public function test_it_should_construct_a_vlv_helper(): void
    {
        self::expectNotToPerformAssertions();

        $this->subject->vlv(
            Operations::search(Filters::equal(
                'foo',
                'bar'
            )),
            'cn',
            100
        );
    }

    public function test_it_should_construct_a_dirsync_helper(): void
    {
        self::expectNotToPerformAssertions();

        $this->subject->dirSync();
    }

    public function test_it_should_construct_a_range_retrieval_helper(): void
    {
        self::expectNotToPerformAssertions();

        $this->subject->range();
    }
    
    public function test_it_should_start_tls(): void
    {
        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::extended(ExtendedRequest::OID_START_TLS))
            ->willReturn(null);

        $this->subject->startTls();;
    }

    public function test_it_should_unbind_if_requested(): void
    {
        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(new UnbindRequest())
            ->willReturn(null);

        $this->subject->unbind();
    }

    public function test_it_should_return_a_whoami(): void
    {
        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::extended(ExtendedRequest::OID_WHOAMI))
            ->willReturn(new LdapMessageResponse(
                1,
                new ExtendedResponse(
                    new LdapResult(0, ''),
                    null,
                    'foo'
                )
            ));

        self::assertSame(
            'foo',
            $this->subject->whoami(),
        );
    }

    public function test_it_should_return_a_correct_compare_response_on_a_match(): void
    {
        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::compare(
                'cn=foo',
                'foo',
                'bar'
            ))
            ->willReturn(new LdapMessageResponse(
                1,
                new CompareResponse(ResultCode::COMPARE_TRUE)
            ));

        self::assertTrue(
            $this->subject->compare(
                'cn=foo',
                'foo',
                'bar',
            )
        );
    }

    public function test_it_should_return_a_correct_compare_response_on_a_non_match(): void
    {
        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::compare(
                'cn=foo',
                'foo',
                'bar',
            ))
            ->willReturn(new LdapMessageResponse(
                1,
                new CompareResponse(ResultCode::COMPARE_FALSE)
            ));

        self::assertFalse(
            $this->subject->compare(
                'cn=foo',
                'foo',
                'bar'
            )
        );
    }

    public function test_it_should_send_a_modify_operation_on_update(): void
    {
        $entry = Entry::create('cn=foo,dc=local', ['cn' => 'foo']);
        $entry->set('sn', 'bar');

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::modify(
                $entry->getDn(),
                ...$entry->changes()
            ))
            ->willReturn(new LdapMessageResponse(
                1,
                new ModifyResponse(ResultCode::SUCCESS)
            ));

        $this->subject->update($entry);
    }

    public function test_it_should_send_an_add_operation_on_create(): void
    {
        $entry = Entry::create('cn=foo,dc=local', ['cn' => 'foo']);

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::add($entry))
            ->willReturn(new LdapMessageResponse(
                1,
                new AddResponse(ResultCode::SUCCESS)
            ));

        $this->subject->create($entry);
    }

    public function test_it_should_send_a_delete_operation_on_delete(): void
    {
        $entry = new Entry('cn=foo,dc=local');

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::delete('cn=foo,dc=local'))
            ->willReturn(new LdapMessageResponse(
                1,
                new DeleteResponse(ResultCode::SUCCESS)
            ));

        $this->subject->delete($entry->getDn()->toString());
    }

    public function test_it_should_send_a_modify_dn_operation_on_move(): void
    {
        $entry = new Entry('cn=foo,dc=local');
        $parent = new Entry('cn=bar,dc=local');

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::move('cn=foo,dc=local', 'cn=bar,dc=local'))
            ->willReturn(new LdapMessageResponse(
                1,
                new ModifyDnResponse(ResultCode::SUCCESS)
            ));

        $this->subject->move(
            $entry,
            $parent,
        );
    }

    public function test_it_should_send_a_modify_dn_operation_on_rename(): void
    {
        $entry = new Entry('cn=foo,dc=local');
        $newRdn = 'cn=bar';

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::rename('cn=foo,dc=local', 'cn=bar'))
            ->willReturn(new LdapMessageResponse(
                1,
                new ModifyDnResponse(ResultCode::SUCCESS)
            ));

        $this->subject->rename(
            $entry,
            $newRdn,
        );
    }

    public function test_it_should_send_a_base_search_on_a_read_and_return_an_entry(): void
    {
        $entry = new Entry('cn=foo,dc=local');

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::read('cn=foo,dc=local'))
            ->willReturn($this::makeSearchResponseFromEntries(new Entries($entry)));

        self::assertEquals(
            $entry,
            $this->subject->read($entry->getDn()->toString())
        );
    }

    public function test_it_should_send_a_read_to_the_RootDSE_if_it_is_called_with_no_arguments(): void
    {
        $entry = new Entry('');

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::read(''))
            ->willReturn($this::makeSearchResponseFromEntries(new Entries($entry)));

        self::assertSame(
            $entry,
            $this->subject->read()
        );
    }

    public function test_it_should_send_a_base_search_on_a_read_and_return_null_if_it_does_not_exist(): void
    {
        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::read('cn=foo,dc=local'))
            ->willThrowException(new OperationException(
                '',
                ResultCode::NO_SUCH_OBJECT
            ));

        $entry = new Entry('cn=foo,dc=local');

        self::assertNull(
            $this->subject->read($entry->getDn()->toString())
        );
    }

    public function test_it_should_throw_an_exception_on_read_or_fail_if_the_entry_does_not_exist(): void
    {
        $exception = new OperationException('', ResultCode::NO_SUCH_OBJECT);

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::read('cn=foo,dc=local'))
            ->willThrowException($exception);

        $this->expectExceptionObject($exception);

        $this->subject->readOrFail('cn=foo,dc=local');;
    }

    public function test_it_should_return_an_entry_on_a_readOrFail_if_it_exists(): void
    {
        $entry = new Entry('cn=foo,dc=local');

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::read('cn=foo,dc=local'))
            ->willReturn($this::makeSearchResponseFromEntries(new Entries($entry)));

        self::assertSame(
            $entry,
            $this->subject->readOrFail($entry->getDn()->toString()),
        );
    }

    public function test_it_should_send_a_base_search_on_a_read_and_throw_an_unrelated_operation_exception(): void
    {
        $entry = new Entry('cn=foo,dc=local');

        $this->mockHandler
            ->expects($this->once())
            ->method('send')
            ->with(Operations::read('cn=foo,dc=local'))
            ->willThrowException(new OperationException(
                '',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS
            ));

        $this->expectException(OperationException::class);

        $this->subject->read($entry->getDn()->toString());;
    }

    public function test_it_should_get_the_default_options(): void
    {
        self::assertSame(
            [
                'version' => 3,
                'servers' => [],
                'port' => 389,
                'transport' => 'tcp',
                'base_dn' => null,
                'page_size' => 1000,
                'use_ssl' => false,
                'ssl_validate_cert' => true,
                'ssl_allow_self_signed' => false,
                'ssl_ca_cert' => null,
                'ssl_peer_name' => null,
                'timeout_connect' => 3,
                'timeout_read' => 10,
                'referral' => 'throw',
                'referral_chaser' => null,
                'referral_limit' => 10,
            ],
            $this->subject->getOptions()->toArray(),
        );
    }

    public function test_it_should_set_the_options(): void
    {
        $options = (new ClientOptions())
            ->setServers([
                'foo',
                'bar',
            ]);

        $this->subject->setOptions($options);

        self::assertSame(
            $options,
            $this->subject->getOptions(),
        );
    }

    public function test_it_should_construct_a_syncrepl_helper(): void
    {
        $syncRequest = Filters::present('foo');

        self::assertEquals(
            new SyncRepl(
                $this->subject,
                $syncRequest,
            ),
            $this->subject->syncRepl($syncRequest),
        );
        self::assertEquals(
            new SyncRepl($this->subject),
            $this->subject->syncRepl(),
        );
    }
}
