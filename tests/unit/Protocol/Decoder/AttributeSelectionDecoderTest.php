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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\AdminLimitExceededException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Decoder\AttributeSelectionDecoder;
use PHPUnit\Framework\TestCase;

use function array_map;
use function range;

final class AttributeSelectionDecoderTest extends TestCase
{
    private AttributeSelectionDecoder $subject;

    protected function setUp(): void
    {
        $this->subject = new AttributeSelectionDecoder();
    }

    public function testItDecodesTheAttributeNames(): void
    {
        self::assertSame(
            ['cn', 'sn', '*'],
            $this->subject->decode(Asn1::sequence(
                Asn1::octetString('cn'),
                Asn1::octetString('sn'),
                Asn1::octetString('*'),
            )),
        );
    }

    public function testItDecodesAsManyNamesAsTheLimitAllows(): void
    {
        self::assertCount(
            AttributeSelectionDecoder::MAX_ATTRIBUTES,
            $this->subject->decode(self::selectionOf(AttributeSelectionDecoder::MAX_ATTRIBUTES)),
        );
    }

    public function testItRefusesMoreNamesThanTheLimitAsAnAdministrativeLimit(): void
    {
        $this->expectException(AdminLimitExceededException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);
        $this->expectExceptionMessage('The request selects more than 1000 attributes.');

        $this->subject->decode(self::selectionOf(AttributeSelectionDecoder::MAX_ATTRIBUTES + 1));
    }

    public function testItRefusesANameThatIsNotAnOctetString(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('An attribute selection must contain octet string values.');

        $this->subject->decode(Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::integer(1),
        ));
    }

    private static function selectionOf(int $count): SequenceType
    {
        return Asn1::sequence(...array_map(
            static fn(int $i): OctetStringType => Asn1::octetString("attr{$i}"),
            range(
                1,
                $count,
            ),
        ));
    }
}
