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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\SortingControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SortingControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private SortingControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SortingControlDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheSortKeys(): void
    {
        self::assertEquals(
            new SortingControl(
                new SortKey('foo'),
                new SortKey('bar'),
                new SortKey(
                    'foobar',
                    true,
                    'bleh',
                ),
            ),
            $this->subject->decode(
                self::encodedControl(
                    Control::OID_SORTING,
                    Asn1::sequenceOf(
                        Asn1::sequence(Asn1::octetString('foo')),
                        Asn1::sequence(Asn1::octetString('bar')),
                        Asn1::sequence(
                            Asn1::octetString('foobar'),
                            Asn1::context(
                                0,
                                Asn1::octetString('bleh'),
                            ),
                            Asn1::context(
                                1,
                                Asn1::boolean(true),
                            ),
                        ),
                    ),
                ),
                $this->context,
            )->setValue(null),
        );
    }

    public function testItRefusesAReverseOrderFlagThatIsNotABoolean(): void
    {
        $this->expectException(EncoderException::class);

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SORTING,
                Asn1::sequenceOf(Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::context(
                        1,
                        Asn1::octetString('ab'),
                    ),
                )),
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
            self::encodedControl(
                Control::OID_SORTING,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>, string}>
     */
    public static function malformedValues(): iterable
    {
        yield 'not a sequence' => [
            Asn1::octetString('foo'),
            'The sorting control is malformed.',
        ];
        yield 'a sort key that is not a sequence' => [
            Asn1::sequenceOf(Asn1::octetString('foo')),
            'The sort key is malformed.',
        ];
        yield 'a sort key with no attribute' => [
            Asn1::sequenceOf(Asn1::sequence(Asn1::octetString(''))),
            'The sort key is missing an attribute description.',
        ];
        yield 'a sort key with an unexpected value' => [
            Asn1::sequenceOf(Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::enumerated(1),
            )),
            'The sorting control contains unexpected data.',
        ];
    }
}
