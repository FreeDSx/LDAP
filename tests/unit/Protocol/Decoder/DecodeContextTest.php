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
use FreeDSx\Asn1\Exception\PduElementsException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Exception\AdminLimitExceededException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

use function array_fill;
use function substr;

final class DecodeContextTest extends TestCase
{
    private DecodeContext $subject;

    protected function setUp(): void
    {
        $this->subject = new DecodeContext(3);
    }

    public function testItCompletesAnIncompleteTypeAsTheTypeItIsTold(): void
    {
        self::assertEquals(
            [
                Asn1::octetString('cn'),
                Asn1::octetString('foo'),
            ],
            $this->subject->complete(
                self::incompleteSequence(),
                AbstractType::TAG_TYPE_SEQUENCE,
            )->getChildren(),
        );
    }

    public function testItDecodesEncodedBytes(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::integer(5),
                Asn1::boolean(true),
            ),
            $this->subject->decode((new LdapEncoder())->encode(Asn1::sequence(
                Asn1::integer(5),
                Asn1::boolean(true),
            ))),
        );
    }

    public function testItRefusesEmptyBytesAsMalformed(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The data to decode cannot be empty.');

        $this->subject->decode('');
    }

    public function testItDecodesNestedPartsHoldingExactlyTheBudget(): void
    {
        self::assertCount(
            3,
            $this->subject->decode(self::sequenceOf(3))->getChildren(),
        );
    }

    public function testOneBudgetIsSharedAcrossEveryDecode(): void
    {
        $this->subject->decode(self::sequenceOf(2));

        $this->expectException(AdminLimitExceededException::class);
        $this->expectExceptionMessage('The request holds more elements than the server allows.');

        $this->subject->decode(self::sequenceOf(2));
    }

    public function testACompletedTypeIsChargedToTheBudget(): void
    {
        $this->subject->complete(
            self::incompleteSequence(),
            AbstractType::TAG_TYPE_SEQUENCE,
        );

        $this->expectException(AdminLimitExceededException::class);

        $this->subject->decode(self::sequenceOf(2));
    }

    public function testASpentBudgetStillAllowsAPrimitive(): void
    {
        $this->subject->decode(self::sequenceOf(3));

        self::assertEquals(
            Asn1::octetString('foo'),
            $this->subject->decode((new LdapEncoder())->encode(Asn1::octetString('foo'))),
        );
    }

    public function testASpentBudgetRefusesASingleElement(): void
    {
        $this->subject->decode(self::sequenceOf(3));

        $this->expectException(AdminLimitExceededException::class);

        $this->subject->decode(self::sequenceOf(1));
    }

    public function testADecodePastTheBudgetIsRefusedBeforeItIsBuilt(): void
    {
        try {
            $this->subject->decode(self::sequenceOf(5));
            self::fail('The decode should have been refused.');
        } catch (AdminLimitExceededException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
            self::assertInstanceOf(
                PduElementsException::class,
                $e->getPrevious(),
            );
        }
    }

    public function testWithoutABudgetItDecodesAnyNumberOfElements(): void
    {
        self::assertCount(
            1_000,
            (new DecodeContext())->decode(self::sequenceOf(1_000))->getChildren(),
        );
    }

    private static function sequenceOf(int $count): string
    {
        return (new LdapEncoder())->encode(Asn1::sequence(...array_fill(
            0,
            $count,
            Asn1::octetString('a'),
        )));
    }

    private static function incompleteSequence(): IncompleteType
    {
        $encoded = (new LdapEncoder())->encode(Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::octetString('foo'),
        ));

        return (new IncompleteType(substr(
            $encoded,
            2,
        )))->setIsConstructed(true);
    }
}
