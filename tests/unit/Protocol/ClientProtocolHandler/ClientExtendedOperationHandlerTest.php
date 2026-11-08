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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientExtendedOperationHandler;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Response\TypedExtendedResponseDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientExtendedOperationHandlerTest extends TestCase
{
    private ClientExtendedOperationHandler $subject;

    private ClientQueue&MockObject $mockQueue;

    protected function setUp(): void
    {
        $container = Container::forClient(new ClientOptions());
        $this->mockQueue = $this->createMock(ClientQueue::class);

        $this->subject = new ClientExtendedOperationHandler(
            $this->mockQueue,
            $container->get(TypedExtendedResponseDecoder::class),
            $container->get(DecodeContextFactory::class),
        );
    }

    public function test_it_should_handle_a_response_with_no_typed_form(): void
    {
        $response = new LdapMessageResponse(
            1,
            new ExtendedResponse(
                new LdapResult(0),
                'bar',
                'foo',
            ),
        );

        self::assertSame(
            $response,
            $this->subject->handleResponse(
                new LdapMessageRequest(
                    1,
                    new ExtendedRequest(
                        'foo',
                        'bar',
                    ),
                ),
                $response,
            ),
        );
    }

    public function test_it_should_decode_the_typed_response_for_the_request_it_answers(): void
    {
        $result = $this->subject->handleResponse(
            new LdapMessageRequest(
                1,
                new ExtendedRequest(ExtendedRequest::OID_PWD_MODIFY),
            ),
            new LdapMessageResponse(
                1,
                self::passwordModifyResponse(new LdapResult(0)),
            ),
        )?->getResponse();

        self::assertInstanceOf(
            PasswordModifyResponse::class,
            $result,
        );
        self::assertSame(
            'bleep-blorp',
            $result->getGeneratedPassword(),
        );
    }

    public function test_it_should_decode_a_typed_response_that_carries_a_referral(): void
    {
        $result = $this->subject->handleResponse(
            new LdapMessageRequest(
                1,
                new ExtendedRequest(ExtendedRequest::OID_PWD_MODIFY),
            ),
            new LdapMessageResponse(
                1,
                self::passwordModifyResponse(new LdapResult(
                    0,
                    '',
                    '',
                    new LdapUrl('foo'),
                )),
            ),
        )?->getResponse();

        self::assertInstanceOf(
            PasswordModifyResponse::class,
            $result,
        );
        self::assertEquals(
            [new LdapUrl('foo')],
            $result->getReferrals(),
        );
    }

    public function test_it_should_handle_an_extended_request_that_has_a_typed_response(): void
    {
        $extendedRequest = new LdapMessageRequest(
            1,
            new ExtendedRequest(ExtendedRequest::OID_PWD_MODIFY),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo($extendedRequest));
        $this->mockQueue
            ->method('getMessage')
            ->willReturn(new LdapMessageResponse(
                1,
                self::passwordModifyResponse(new LdapResult(0)),
            ));

        self::assertInstanceOf(
            PasswordModifyResponse::class,
            $this->subject->handleRequest($extendedRequest)?->getResponse(),
        );
    }

    public function test_it_should_refuse_a_response_that_is_not_an_extended_response(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willReturn(new LdapMessageResponse(
                1,
                new DeleteResponse(0),
            ));

        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('Expected an extended response to the extended request.');

        $this->subject->handleRequest(new LdapMessageRequest(
            1,
            new ExtendedRequest(ExtendedRequest::OID_PWD_MODIFY),
        ));
    }

    private static function passwordModifyResponse(LdapResult $result): ExtendedResponse
    {
        return new ExtendedResponse(
            $result,
            null,
            (new LdapEncoder())->encode(Asn1::sequence(Asn1::context(
                0,
                Asn1::octetString('bleep-blorp'),
            ))),
        );
    }
}
