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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Request\CancelRequestDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class CancelRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private CancelRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(CancelRequestDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheMessageIdToCancel(): void
    {
        self::assertEquals(
            new CancelRequest(2),
            $this->subject->decode(
                (new LdapEncoder())->encode(Asn1::sequence(Asn1::integer(2))),
                $this->context,
            ),
        );
    }

    public function testItRefusesAMessageIdWiderThanAnInteger(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The cancel request message ID is not an integer.');

        $this->subject->decode(
            "\x30\x0b\x02\x09\x01" . str_repeat(
                "\x00",
                8,
            ),
            $this->context,
        );
    }

    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(?string $value): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            $value,
            $this->context,
        );
    }

    /**
     * @return array<string, array{?string}>
     */
    public static function malformedValues(): array
    {
        $encoder = new LdapEncoder();

        return [
            'no value' => [null],
            'not a sequence' => [$encoder->encode(Asn1::octetString('foo'))],
            'an empty sequence' => [$encoder->encode(Asn1::sequence())],
            'a message ID that is not an integer' => [$encoder->encode(Asn1::sequence(Asn1::octetString('bar')))],
            'not BER' => ["\x01\x02\x03"],
            'empty' => [''],
        ];
    }
}
