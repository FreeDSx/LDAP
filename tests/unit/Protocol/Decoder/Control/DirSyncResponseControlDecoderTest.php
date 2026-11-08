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
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\DirSyncResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class DirSyncResponseControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private DirSyncResponseControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(DirSyncResponseControlDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheMoreResultsUnusedAndCookie(): void
    {
        self::assertEquals(
            new DirSyncResponseControl(
                1,
                0,
                'foo',
            ),
            $this->subject->decode(
                self::encodedControl(
                    Control::OID_DIR_SYNC,
                    Asn1::sequence(
                        Asn1::integer(1),
                        Asn1::integer(0),
                        Asn1::octetString('foo'),
                    ),
                ),
                $this->context,
            )->setValue(null),
        );
    }

    #[DataProvider('wideFields')]
    #[RequiresPhpExtension('gmp')]
    public function testItRefusesAFieldWiderThanAnInteger(
        SequenceType $value,
        string $message,
    ): void {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage($message);

        $this->subject->decode(
            self::encodedControl(
                Control::OID_DIR_SYNC,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{SequenceType, string}>
     */
    public static function wideFields(): iterable
    {
        yield 'more results' => [
            Asn1::sequence(
                Asn1::integer('18446744073709551616'),
                Asn1::integer(0),
                Asn1::octetString(''),
            ),
            'The DirSyncResponse more results value is not an integer.',
        ];
        yield 'unused' => [
            Asn1::sequence(
                Asn1::integer(0),
                Asn1::integer('18446744073709551616'),
                Asn1::octetString(''),
            ),
            'The DirSyncResponse unused value is not an integer.',
        ];
    }

    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(
        SequenceType $value,
        string $message,
    ): void {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage($message);

        $this->subject->decode(
            self::encodedControl(
                Control::OID_DIR_SYNC,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{SequenceType, string}>
     */
    public static function malformedValues(): iterable
    {
        yield 'more results that is not an integer' => [
            Asn1::sequence(
                Asn1::octetString('1'),
                Asn1::integer(0),
                Asn1::octetString(''),
            ),
            'A DirSyncResponse control value sequence 0 must be an integer type.',
        ];
        yield 'unused that is not an integer' => [
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::octetString('0'),
                Asn1::octetString(''),
            ),
            'A DirSyncResponse control value sequence 1 must be an integer type.',
        ];
        yield 'no cookie' => [
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer(0),
            ),
            'A DirSyncResponse control value sequence 2 must be an octet string type.',
        ];
    }
}
