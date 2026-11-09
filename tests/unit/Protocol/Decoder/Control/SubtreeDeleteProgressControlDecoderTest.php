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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\SubtreeDeleteProgressControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SubtreeDeleteProgressControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private SubtreeDeleteProgressControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SubtreeDeleteProgressControlDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheDeletedCount(): void
    {
        $control = $this->subject->decode(
            (new SubtreeDeleteProgressControl(25000))->toAsn1(),
            $this->context,
        );

        self::assertSame(
            [25000, null],
            [
                $control->getDeleted(),
                $control->getRemaining(),
            ],
        );
    }

    public function testItDecodesTheRemainingCount(): void
    {
        self::assertSame(
            12,
            $this->subject->decode(
                (new SubtreeDeleteProgressControl(
                    25000,
                    12,
                ))->toAsn1(),
                $this->context,
            )->getRemaining(),
        );
    }

    #[RequiresPhpExtension('gmp')]
    public function testItReadsARemainingCountWiderThanAnIntegerAsAbsent(): void
    {
        self::assertNull($this->subject->decode(
            self::encodedControl(
                Control::OID_SUBTREE_DELETE_PROGRESS,
                Asn1::sequence(
                    Asn1::integer(25000),
                    Asn1::context(
                        0,
                        Asn1::integer('18446744073709551616'),
                    ),
                ),
            ),
            $this->context,
        )->getRemaining());
    }

    #[RequiresPhpExtension('gmp')]
    public function testItRefusesADeletedCountWiderThanAnInteger(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The subtree delete progress deleted count is not an integer.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SUBTREE_DELETE_PROGRESS,
                Asn1::sequence(Asn1::integer('18446744073709551616')),
            ),
            $this->context,
        );
    }

    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(SequenceType $value): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The subtree delete progress control is malformed.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SUBTREE_DELETE_PROGRESS,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{SequenceType}>
     */
    public static function malformedValues(): iterable
    {
        yield 'a deleted count that is not an integer' => [Asn1::sequence(Asn1::octetString('25000'))];
        yield 'a remaining count with the wrong tag' => [Asn1::sequence(
            Asn1::integer(25000),
            Asn1::context(
                1,
                Asn1::integer(12),
            ),
        )];
    }
}
