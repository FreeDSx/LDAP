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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\ReadEntryControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;

final class ReadEntryControlDecoderTest extends TestCase
{
    use EncodedControlTrait;

    private ReadEntryControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = new ReadEntryControlDecoder(PostReadControl::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheAttributeSelection(): void
    {
        $control = $this->subject->decode(
            (new PostReadControl(
                'cn',
                'sn',
                'mail',
            ))->toAsn1(),
            $this->context,
        );

        self::assertSame(
            [PostReadControl::class, ['cn', 'sn', 'mail'], Control::OID_POST_READ],
            [
                $control::class,
                $control->getAttributes(),
                $control->getTypeOid(),
            ],
        );
    }

    public function testItDecodesAnEmptyAttributeSelection(): void
    {
        self::assertSame(
            [],
            $this->subject->decode(
                (new PostReadControl())->toAsn1(),
                $this->context,
            )->getAttributes(),
        );
    }

    public function testItBuildsTheControlClassItIsGiven(): void
    {
        self::assertInstanceOf(
            PreReadControl::class,
            (new ReadEntryControlDecoder(PreReadControl::class))->decode(
                (new PreReadControl('cn'))->toAsn1(),
                $this->context,
            ),
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
                Control::OID_POST_READ,
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
            Asn1::octetString('cn'),
            'A read-entry control value must be a sequence of attribute names.',
        ];
        yield 'an attribute that is not an octet string' => [
            Asn1::sequence(Asn1::integer(1)),
            'A read-entry attribute selection must contain octet string values.',
        ];
    }
}
