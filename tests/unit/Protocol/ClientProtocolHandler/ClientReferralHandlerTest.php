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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\Exception\SkipReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientReferralHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\ReferralChaserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ClientReferralHandlerTest extends TestCase
{
    private ClientReferralHandler $subject;

    private ReferralChaserInterface&MockObject $mockChaser;

    private LdapClient&MockObject $mockLdapClient;

    private ClientOptions $options;

    protected function setUp(): void
    {
        $this->mockChaser = $this->createMock(ReferralChaserInterface::class);
        $this->mockLdapClient = $this->createMock(LdapClient::class);

        $this->mockChaser
            ->method('client')
            ->willReturn($this->mockLdapClient);

        $this->options = new ClientOptions();
        $this->subject = new ClientReferralHandler($this->options);
    }

    public function test_it_should_throw_an_exception_on_referrals(): void
    {
        $this->subject = new ClientReferralHandler(
            $this->options->setReferral('throw')
        );

        $response = new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', 'foo', new LdapUrl('foo')));
        $request = new LdapMessageRequest(1, new DeleteRequest('cn=foo'));

        self::expectException(ReferralException::class);

        $this->subject->handleResponse(
            $request,
            $response,
        );
    }

    public function test_it_should_follow_referrals_with_a_referral_chaser_if_specified(): void
    {
        $this->options
            ->setReferral('follow')
            ->setReferralLimit(10)
            ->setReferralChaser($this->mockChaser);

        $bind = new SimpleBindRequest('foo', 'bar');
        $this->mockChaser
            ->expects(self::once())
            ->method('chase')
            ->willReturn($bind);

        $message = new LdapMessageResponse(2, new DeleteResponse(0));

        $this->mockLdapClient
            ->method('send')
            ->will(self::onConsecutiveCalls(
                null,
                $message
            ));

        self::assertEquals(
            $message,
            $this->subject->handleResponse(
                new LdapMessageRequest(2, new DeleteRequest('foo')),
                new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', '', new LdapUrl('foo')))
            )
        );
    }

    public function test_it_should_throw_an_exception_if_the_referral_limit_is_reached(): void
    {
        $this->options
            ->setReferral('follow')
            ->setReferralLimit(-1)
            ->setReferralChaser($this->mockChaser);

        self::expectExceptionObject(new OperationException(
            'The referral limit of -1 has been reached.'
        ));

        $this->subject->handleResponse(
            new LdapMessageRequest(
                2,
                new DeleteRequest('foo')
            ),
            new LdapMessageResponse(
                1,
                new DeleteResponse(
                    ResultCode::REFERRAL,
                    '',
                    '',
                    new LdapUrl('foo')
                )
            ),
        );
    }

    public function test_it_should_throw_an_exception_if_all_referrals_have_been_tried_and_follow_is_specified(): void
    {
        $this->mockChaser
            ->method('chase')
            ->willThrowException(new SkipReferralException());

        $this->options
            ->setReferral('follow')
            ->setReferralLimit(10)
            ->setReferralChaser($this->mockChaser);

        self::expectExceptionObject(new OperationException(
            'All referral attempts have been exhausted. ',
            ResultCode::REFERRAL
        ));

        $this->subject->handleResponse(
            new LdapMessageRequest(
                2,
                new DeleteRequest('foo')
            ),
            new LdapMessageResponse(
                1,
                new DeleteResponse(
                    ResultCode::REFERRAL,
                    '',
                    '',
                    new LdapUrl('foo')
                )
            ),
        );
    }

    public function test_it_should_continue_to_the_next_referral_if_a_connection_exception_is_thrown(): void
    {
        $this->options
            ->setReferral('follow')
            ->setReferralLimit(10)
            ->setReferralChaser($this->mockChaser);

        $bind = new SimpleBindRequest('foo', 'bar');

        $this->mockChaser
            ->method('chase')
            ->willReturn($bind);

        $message = new LdapMessageResponse(2, new DeleteResponse(0));

        $this->mockLdapClient
            ->method('send')
            ->will(self::onConsecutiveCalls(
                self::throwException(new ConnectionException()),
                $message,
                $message,
            ));

        self::assertEquals(
            $message,
            $this->subject->handleResponse(
                new LdapMessageRequest(
                    1,
                    new DeleteRequest('foo')
                ),
                new LdapMessageResponse(
                    1,
                    new DeleteResponse(
                        ResultCode::REFERRAL,
                        '',
                        '',
                        new LdapUrl('foo'),
                        new LdapUrl('bar'),
                    )
                ),
            ),
        );
    }

    public function test_it_should_continue_to_the_next_referral_if_an_operation_exception_with_a_referral_result_code_is_thrown(): void
    {
        $this->options
            ->setReferral('follow')
            ->setReferralLimit(10)
            ->setReferralChaser($this->mockChaser);

        $bind = new SimpleBindRequest('foo', 'bar');

        $this->mockChaser
            ->method('chase')
            ->willReturn($bind);

        $message = new LdapMessageResponse(2, new DeleteResponse(0));

        $this->mockLdapClient
            ->method('send')
            ->will(self::onConsecutiveCalls(
                self::throwException(new OperationException('fail', ResultCode::REFERRAL)),
                $message,
                $message,
            ));

        self::assertEquals(
            $message,
            $this->subject->handleResponse(
                new LdapMessageRequest(
                    1,
                    new DeleteRequest('foo')
                ),
                new LdapMessageResponse(
                    1,
                    new DeleteResponse(
                        ResultCode::REFERRAL,
                        '',
                        '',
                        new LdapUrl('foo'),
                        new LdapUrl('bar'),
                    )
                ),
            ),
        );
    }

    public function test_it_should_not_bind_on_the_referral_client_initially_if_the_referral_is_for_a_bind_request(): void
    {
        $this->options
            ->setReferral('follow')
            ->setReferralLimit(10)
            ->setReferralChaser($this->mockChaser);

        $this->mockChaser
            ->method('chase')
            ->willReturn(new SimpleBindRequest('foo', 'bar'));

        $message = new LdapMessageResponse(1, new BindResponse(new LdapResult(0)));

        $this->mockLdapClient
            ->expects(self::once())
            ->method('send')
            ->with(new SimpleBindRequest('foo', 'bar'))
            ->willReturn($message);

        self::assertEquals(
            $message,
            $this->subject->handleResponse(
                new LdapMessageRequest(
                    1,
                    new SimpleBindRequest(
                        'foo',
                        'bar'
                    )
                ),
                new LdapMessageResponse(
                    1,
                    new BindResponse(
                        new LdapResult(
                            ResultCode::REFERRAL,
                            '',
                            '',
                            new LdapUrl('foo')
                        )
                    )
                )
            )
        );
    }

    public function test_it_should_ignore_referrals_and_return_null_when_ignore_is_set(): void
    {
        $this->subject = new ClientReferralHandler(
            $this->options->setReferral('ignore')
        );

        $response = new LdapMessageResponse(1, new DeleteResponse(ResultCode::REFERRAL, '', 'foo', new LdapUrl('foo')));
        $request = new LdapMessageRequest(1, new DeleteRequest('cn=foo'));

        self::assertNull(
            $this->subject->handleResponse($request, $response)
        );
    }

    public function test_it_should_map_ldap_url_scope_base_to_scope_base_object(): void
    {
        $this->options
            ->setReferral('follow')
            ->setReferralLimit(10)
            ->setReferralChaser($this->mockChaser);

        $referralUrl = new LdapUrl('foo');
        $referralUrl->setScope(LdapUrl::SCOPE_BASE);
        $referralUrl->setDn('cn=foo,dc=example,dc=com');

        $this->mockChaser->method('chase')->willReturn(null);

        $sentRequest = null;
        $this->mockLdapClient
            ->method('send')
            ->willReturnCallback(function (SearchRequest $req) use (&$sentRequest) {
                $sentRequest = $req;
                return new LdapMessageResponse(2, new SearchResultDone(0));
            });

        $this->subject->handleResponse(
            new LdapMessageRequest(1, new SearchRequest(Filters::present('objectClass'))),
            new LdapMessageResponse(1, new SearchResultDone(ResultCode::REFERRAL, '', '', $referralUrl))
        );

        self::assertInstanceOf(SearchRequest::class, $sentRequest);
        self::assertSame(
            SearchRequest::SCOPE_BASE_OBJECT,
            $sentRequest->getScope(),
        );
    }

    public function test_it_should_map_ldap_url_scope_one_to_scope_single_level(): void
    {
        $this->options
            ->setReferral('follow')
            ->setReferralLimit(10)
            ->setReferralChaser($this->mockChaser);

        $referralUrl = new LdapUrl('foo');
        $referralUrl->setScope(LdapUrl::SCOPE_ONE);
        $referralUrl->setDn('cn=foo,dc=example,dc=com');

        $this->mockChaser->method('chase')->willReturn(null);

        $sentRequest = null;
        $this->mockLdapClient
            ->method('send')
            ->willReturnCallback(function (SearchRequest $req) use (&$sentRequest) {
                $sentRequest = $req;
                return new LdapMessageResponse(2, new SearchResultDone(0));
            });

        $this->subject->handleResponse(
            new LdapMessageRequest(1, new SearchRequest(Filters::present('objectClass'))),
            new LdapMessageResponse(1, new SearchResultDone(ResultCode::REFERRAL, '', '', $referralUrl))
        );

        self::assertInstanceOf(SearchRequest::class, $sentRequest);
        self::assertSame(
            SearchRequest::SCOPE_SINGLE_LEVEL,
            $sentRequest->getScope(),
        );
    }

    public function test_it_should_send_the_modified_cloned_request_with_referral_dn(): void
    {
        $this->options
            ->setReferral('follow')
            ->setReferralLimit(10)
            ->setReferralChaser($this->mockChaser);

        $referralUrl = new LdapUrl('foo');
        $referralUrl->setDn('cn=referral-target,dc=example,dc=com');

        $this->mockChaser->method('chase')->willReturn(null);

        $sentRequest = null;
        $this->mockLdapClient
            ->method('send')
            ->willReturnCallback(function (SearchRequest $req) use (&$sentRequest) {
                $sentRequest = $req;
                return new LdapMessageResponse(2, new SearchResultDone(0));
            });

        $originalRequest = new SearchRequest(Filters::present('objectClass'));
        $originalRequest->setBaseDn('cn=original,dc=example,dc=com');

        $this->subject->handleResponse(
            new LdapMessageRequest(1, $originalRequest),
            new LdapMessageResponse(1, new SearchResultDone(ResultCode::REFERRAL, '', '', $referralUrl))
        );

        self::assertInstanceOf(SearchRequest::class, $sentRequest);
        self::assertSame(
            'cn=referral-target,dc=example,dc=com',
            (string) $sentRequest->getBaseDn(),
        );
        self::assertSame(
            'cn=original,dc=example,dc=com',
            (string) $originalRequest->getBaseDn(),
        );
    }
}
