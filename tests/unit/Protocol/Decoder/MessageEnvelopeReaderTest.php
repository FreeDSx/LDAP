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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\FilterTooWideException;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Decoder\Control\ControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\MessageEnvelope;
use FreeDSx\Ldap\Protocol\Decoder\MessageEnvelopeReader;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessage;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Throwable;

final class MessageEnvelopeReaderTest extends TestCase
{
    private MessageEnvelopeReader $subject;

    private DecodeContext $context;

    private ControlDecoder $controls;

    protected function setUp(): void
    {
        $this->subject = new MessageEnvelopeReader();
        $this->context = new DecodeContext(new LdapEncoder());
        $this->controls = new ControlDecoder([]);
    }

    public function testItReadsTheMessageIdAndTheOperation(): void
    {
        $envelope = $this->subject->read(self::received(Asn1::sequence(
            Asn1::integer(7),
            Asn1::application(
                10,
                Asn1::octetString('dc=foo,dc=bar'),
            ),
        )));

        self::assertSame(
            [7, 10, 'dc=foo,dc=bar'],
            [$envelope->messageId, $envelope->operationTag, $envelope->operation->getValue()],
        );
    }

    public function testItRefusesAMessageThatIsNotASequence(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('Expected an ASN1 sequence type, but got: FreeDSx\Asn1\Type\OctetStringType');

        $this->subject->read(Asn1::octetString('x'));
    }

    public function testItRefusesAMessageWithoutAnOperation(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('Expected an ASN1 sequence with at least 2 elements, but it has 1');

        $this->subject->read(Asn1::sequence(Asn1::integer(1)));
    }

    public function testItRefusesAMessageIdThatIsNotAnInteger(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('Expected an LDAP message ID as an ASN.1 integer type. None received.');

        $this->subject->read(Asn1::sequence(
            Asn1::octetString('1'),
            Asn1::application(
                10,
                Asn1::octetString('dc=foo,dc=bar'),
            ),
        ));
    }

    #[DataProvider('outOfRangeMessageIds')]
    public function testItRefusesAMessageIdOutsideThePermittedRange(int $messageId): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The LDAP message ID is outside the range it is permitted to use.');

        $this->subject->read(Asn1::sequence(
            Asn1::integer($messageId),
            Asn1::application(
                10,
                Asn1::octetString('dc=foo,dc=bar'),
            ),
        ));
    }

    public static function outOfRangeMessageIds(): Generator
    {
        yield 'negative' => [-1];
        yield 'above maxInt' => [LdapMessage::MAX_INT + 1];
    }

    #[DataProvider('inRangeMessageIds')]
    public function testItAcceptsAMessageIdAtTheEdgeOfThePermittedRange(int $messageId): void
    {
        self::assertSame(
            $messageId,
            $this->subject->read(Asn1::sequence(
                Asn1::integer($messageId),
                Asn1::application(
                    10,
                    Asn1::octetString('dc=foo,dc=bar'),
                ),
            ))->messageId,
        );
    }

    public static function inRangeMessageIds(): Generator
    {
        yield 'zero' => [0];
        yield 'maxInt' => [LdapMessage::MAX_INT];
    }

    public function testItNamesAnOperationTagThisSideDoesNotDecode(): void
    {
        self::assertSame(
            'The tag 30 for the LDAP operation is not supported.',
            $this->subject->unsupported(30)->getMessage(),
        );
    }

    public function testItReturnsWhatTheDecodingPastTheEnvelopeReturns(): void
    {
        self::assertSame(
            'decoded',
            $this->subject->answerable(
                self::deleteEnvelope(),
                static fn(): string => 'decoded',
            ),
        );
    }

    public function testAnAnswerableFailureNamesTheMessageAndKeepsItsResultCode(): void
    {
        $e = $this->answerableFailureOf(new FilterTooWideException('The filter holds more than 1000 items.'));

        self::assertSame(
            [9, 10, ResultCode::ADMIN_LIMIT_EXCEEDED, 'The filter holds more than 1000 items.'],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode(), $e->getMessage()],
        );
    }

    public function testAProtocolFailureNamesTheMessageAsAProtocolError(): void
    {
        $e = $this->answerableFailureOf(new ProtocolException('The delete request is malformed.'));

        self::assertSame(
            [9, 10, ResultCode::PROTOCOL_ERROR, 'The delete request is malformed.'],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode(), $e->getMessage()],
        );
    }

    public function testAnEncoderFailureNamesTheMessageAsAProtocolError(): void
    {
        $e = $this->answerableFailureOf(new EncoderException('The encoded sequence type is malformed.'));

        self::assertSame(
            [9, 10, ResultCode::PROTOCOL_ERROR, 'The encoded sequence type is malformed.'],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode(), $e->getMessage()],
        );
    }

    public function testAnyOtherFailureIsNotMadeAnswerable(): void
    {
        $this->expectException(RuntimeException::class);

        $this->subject->answerable(
            self::deleteEnvelope(),
            static fn(): never => throw new RuntimeException('Not a decoding failure.'),
        );
    }

    public function testItDecodesEachControlInTheOrderSent(): void
    {
        $envelope = $this->subject->read(self::received(Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(
                10,
                Asn1::octetString('dc=foo,dc=bar'),
            ),
            Asn1::context(
                0,
                Asn1::sequenceOf(
                    (new Control('1.2.3'))->toAsn1(),
                    (new Control('4.5.6'))->toAsn1(),
                ),
            ),
        )));

        self::assertSame(
            ['1.2.3', '4.5.6'],
            array_map(
                static fn(Control $control): string => $control->getTypeOid(),
                $this->subject->controlsOf(
                    $envelope,
                    $this->context,
                    $this->controls,
                ),
            ),
        );
    }

    public function testItDecodesTheControlsOfEveryControlsBlockInTheOrderSent(): void
    {
        $envelope = $this->subject->read(self::received(Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(
                10,
                Asn1::octetString('dc=foo,dc=bar'),
            ),
            Asn1::context(
                0,
                Asn1::sequenceOf(
                    (new Control('1.2.3'))->toAsn1(),
                    (new Control('4.5.6'))->toAsn1(),
                ),
            ),
            Asn1::context(
                0,
                Asn1::sequenceOf((new Control('7.8.9'))->toAsn1()),
            ),
        )));

        self::assertSame(
            ['1.2.3', '4.5.6', '7.8.9'],
            array_map(
                static fn(Control $control): string => $control->getTypeOid(),
                $this->subject->controlsOf(
                    $envelope,
                    $this->context,
                    $this->controls,
                ),
            ),
        );
    }

    public function testItIgnoresAComponentAfterTheOperationThatIsNotTheControls(): void
    {
        $envelope = $this->subject->read(self::received(Asn1::sequence(
            Asn1::integer(1),
            Asn1::application(
                10,
                Asn1::octetString('dc=foo,dc=bar'),
            ),
            Asn1::context(
                30,
                Asn1::octetString('extension'),
            ),
        )));

        self::assertSame(
            [],
            $this->subject->controlsOf(
                $envelope,
                $this->context,
                $this->controls,
            ),
        );
    }

    public function testItRefusesControlsThatWereNotLeftUndecoded(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The ASN1 structure for the controls is malformed.');

        $this->subject->controlsOf(
            $this->subject->read(Asn1::sequence(
                Asn1::integer(1),
                Asn1::application(
                    10,
                    Asn1::octetString('dc=foo,dc=bar'),
                ),
                Asn1::context(
                    0,
                    Asn1::sequenceOf((new Control('1.2.3'))->toAsn1()),
                ),
            )),
            $this->context,
            $this->controls,
        );
    }

    public function testItRefusesAControlWithoutAnOid(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The control either is not a sequence or has no OID value attached.');

        $this->subject->controlsOf(
            $this->subject->read(self::received(Asn1::sequence(
                Asn1::integer(1),
                Asn1::application(
                    10,
                    Asn1::octetString('dc=foo,dc=bar'),
                ),
                Asn1::context(
                    0,
                    Asn1::sequenceOf(Asn1::sequence(Asn1::boolean(true))),
                ),
            ))),
            $this->context,
            $this->controls,
        );
    }

    private function answerableFailureOf(Throwable $failure): MessageDecodeException
    {
        try {
            $this->subject->answerable(
                self::deleteEnvelope(),
                static fn(): never => throw $failure,
            );
        } catch (MessageDecodeException $e) {
            return $e;
        }
    }

    private static function deleteEnvelope(): MessageEnvelope
    {
        return new MessageEnvelope(
            Asn1::sequence(
                Asn1::integer(9),
                Asn1::application(
                    10,
                    Asn1::octetString('dc=foo,dc=bar'),
                ),
            ),
            9,
            10,
            Asn1::application(
                10,
                Asn1::octetString('dc=foo,dc=bar'),
            ),
        );
    }

    /**
     * @return AbstractType<mixed>
     */
    private static function received(SequenceType $message): AbstractType
    {
        $encoder = new LdapEncoder();

        return $encoder->decode($encoder->encode($message));
    }
}
