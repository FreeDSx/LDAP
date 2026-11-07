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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Decoder\ResponseMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PHPUnit\Framework\TestCase;

final class ResponseMessageDecoderTest extends TestCase
{
    private ResponseMessageDecoder $subject;

    protected function setUp(): void
    {
        $this->subject = Container::forClient(new ClientOptions())->get(ResponseMessageDecoder::class);
    }

    public function testItDecodesTheResponseAndItsControls(): void
    {
        $message = $this->subject->decode(self::received(new LdapMessageResponse(
            3,
            new DeleteResponse(
                0,
                'dc=foo,dc=bar',
            ),
            new Control('foo'),
        )));

        self::assertEquals(
            new LdapMessageResponse(
                3,
                new DeleteResponse(
                    0,
                    'dc=foo,dc=bar',
                ),
                new Control('foo'),
            ),
            $message,
        );
    }

    public function testItDecodesThePasswordPolicyControlAsItsResponseForm(): void
    {
        $message = $this->subject->decode(self::received(new LdapMessageResponse(
            4,
            new DeleteResponse(0),
            new PwdPolicyResponseControl(error: PwdPolicyError::CHANGE_AFTER_RESET),
        )));

        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $message->controls()->getByClass(PwdPolicyResponseControl::class)?->getError(),
        );
    }

    public function testItDecodesThePostReadControlAsItsResponseForm(): void
    {
        $message = $this->subject->decode(self::received(new LdapMessageResponse(
            4,
            new ModifyResponse(0),
            new PostReadResponseControl(Entry::fromArray(
                'cn=foo,dc=bar',
                ['cn' => 'foo'],
            )),
        )));

        self::assertSame(
            'cn=foo,dc=bar',
            $message->controls()->getByClass(PostReadResponseControl::class)?->getEntry()->getDn()->toString(),
        );
    }

    public function testItDecodesTheSubtreeDeleteProgressControlAsItsTypedClass(): void
    {
        $message = $this->subject->decode(self::received(new LdapMessageResponse(
            4,
            new DeleteResponse(ResultCode::ADMIN_LIMIT_EXCEEDED),
            new SubtreeDeleteProgressControl(25000),
        )));

        self::assertSame(
            25000,
            $message->controls()->getByClass(SubtreeDeleteProgressControl::class)?->getDeleted(),
        );
    }

    public function testARequestOperationIsRefusedBeforeItIsDecoded(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The tag 10 for the LDAP operation is not supported.');

        $this->subject->decode(Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(
                10,
                Asn1::octetString('dc=foo,dc=bar'),
            ),
        ));
    }

    public function testAFailureInsideTheResponseNamesTheMessageItBelongsTo(): void
    {
        try {
            $this->subject->decode(Asn1::sequence(
                Asn1::integer(6),
                Asn1::application(
                    5,
                    Asn1::sequence(
                        Asn1::octetString('0'),
                        Asn1::octetString(''),
                        Asn1::octetString(''),
                    ),
                ),
            ));
            self::fail('The malformed result should have been refused.');
        } catch (MessageDecodeException $e) {
            self::assertSame(
                [6, 5, ResultCode::PROTOCOL_ERROR],
                [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
            );
        }
    }

    /**
     * @return AbstractType<mixed>
     */
    private static function received(LdapMessageResponse $message): AbstractType
    {
        $encoder = new LdapEncoder();

        return $encoder->decode($encoder->encode($message->toAsn1()));
    }
}
