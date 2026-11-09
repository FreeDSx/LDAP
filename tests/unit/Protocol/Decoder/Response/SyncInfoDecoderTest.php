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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Response\SyncInfoDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SyncInfoDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private SyncInfoDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SyncInfoDecoder::class);
        $this->context = new DecodeContext();
    }

    #[DataProvider('messages')]
    public function testItDecodesEachFormOfTheMessage(SyncInfoMessage $message): void
    {
        self::assertEquals(
            $message,
            $this->subject->decode(
                self::received((clone $message)->toAsn1()),
                $this->context,
            ),
        );
    }

    /**
     * @return iterable<string, array{SyncInfoMessage}>
     */
    public static function messages(): iterable
    {
        yield 'a new cookie' => [new SyncNewCookie('omnomnom')];
        yield 'a refresh delete' => [new SyncRefreshDelete(
            false,
            'omnomnom',
        )];
        yield 'a refresh present' => [new SyncRefreshPresent(
            false,
            'omnomnom',
        )];
        yield 'a sync ID set' => [new SyncIdSet(
            ['foo', 'bar'],
            true,
            'omnomnom',
        )];
    }

    public function testItRefusesAMessageWithNoValue(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The SyncInfoMessage must have a value.');

        $this->subject->decode(
            self::message(),
            $this->context,
        );
    }

    public function testItRefusesAnEmptyValueAsMalformed(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The data to decode cannot be empty.');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::context(
                    0,
                    Asn1::octetString(IntermediateResponse::OID_SYNC_INFO),
                ),
                Asn1::context(
                    1,
                    Asn1::octetString(''),
                ),
            ),
            $this->context,
        );
    }

    public function testItRefusesAFormItDoesNotRecognize(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The tag number 4 for a SyncInfoMessage was unexpected.');

        $this->subject->decode(
            self::message(Asn1::context(
                4,
                Asn1::octetString('foo'),
            )),
            $this->context,
        );
    }

    public function testItRefusesASyncIdSetUnderAnotherName(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The response name should be "1.3.6.1.4.1.4203.1.9.1.4", but was "foo".');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::context(
                    0,
                    Asn1::octetString('foo'),
                ),
                Asn1::context(
                    1,
                    Asn1::octetString((new LdapEncoder())->encode(Asn1::context(
                        3,
                        Asn1::sequence(Asn1::setOf()),
                    ))),
                ),
            ),
            $this->context,
        );
    }

    /**
     * @param AbstractType<mixed> $value
     */
    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(
        AbstractType $value,
        string $message,
    ): void {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage($message);

        $this->subject->decode(
            self::message($value),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>, string}>
     */
    public static function malformedValues(): iterable
    {
        yield 'a refresh holding an unexpected value' => [
            Asn1::context(
                2,
                Asn1::sequence(Asn1::integer(1)),
            ),
            'Unexpected value in the refreshPresent response.',
        ];
        yield 'a sync ID set holding an unexpected value' => [
            Asn1::context(
                3,
                Asn1::sequence(Asn1::integer(1)),
            ),
            'Unexpected value in the syncIdSet response.',
        ];
        yield 'a sync ID set without its set' => [
            Asn1::context(
                3,
                Asn1::sequence(Asn1::octetString('cookie')),
            ),
            'Expected a set of entryUuids, but received none.',
        ];
        yield 'a sync ID set holding an entryUUID that is not an octet string' => [
            Asn1::context(
                3,
                Asn1::sequence(Asn1::setOf(Asn1::integer(1))),
            ),
            'The entryUuid needs to be an octet string type.',
        ];
    }

    public function testItRefusesAValueThatIsNotContextTagged(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage(
            'The intermediate response either contains no value or is not an octet string.',
        );

        $this->subject->decode(
            Asn1::sequence(
                Asn1::context(
                    0,
                    Asn1::octetString(IntermediateResponse::OID_SYNC_INFO),
                ),
                Asn1::octetString('foo'),
            ),
            $this->context,
        );
    }

    /**
     * @param AbstractType<mixed> $value
     * @return AbstractType<mixed>
     */
    private static function message(?AbstractType $value = null): AbstractType
    {
        $message = Asn1::sequence(Asn1::context(
            0,
            Asn1::octetString(IntermediateResponse::OID_SYNC_INFO),
        ));
        if ($value !== null) {
            $message->addChild(Asn1::context(
                1,
                Asn1::octetString((new LdapEncoder())->encode($value)),
            ));
        }

        return $message;
    }

    /**
     * @param AbstractType<mixed> $type
     * @return AbstractType<mixed>
     */
    private static function received(AbstractType $type): AbstractType
    {
        $encoder = new LdapEncoder();

        return $encoder->decode($encoder->encode($type));
    }
}
