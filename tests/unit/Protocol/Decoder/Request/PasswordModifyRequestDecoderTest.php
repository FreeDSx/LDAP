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
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Request\PasswordModifyRequestDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class PasswordModifyRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private PasswordModifyRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(PasswordModifyRequestDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    #[DataProvider('requests')]
    public function testItDecodesTheFieldsTheRequestNames(PasswordModifyRequest $request): void
    {
        $result = $this->subject->decode(
            self::valueOf($request),
            $this->context,
        );

        self::assertEquals(
            $request->setValue(null),
            $result->setValue(null),
        );
    }

    /**
     * @return array<string, array{PasswordModifyRequest}>
     */
    public static function requests(): array
    {
        return [
            'every field' => [new PasswordModifyRequest(
                'foo',
                'bar',
                '12345',
            )],
            'no identity' => [new PasswordModifyRequest(
                null,
                'bar',
                '12345',
            )],
            'no old password' => [new PasswordModifyRequest(
                'foo',
                null,
                '12345',
            )],
        ];
    }

    public function testARequestWithNoValueNamesNoField(): void
    {
        self::assertEquals(
            new PasswordModifyRequest(),
            $this->subject->decode(
                null,
                $this->context,
            ),
        );
    }

    #[DataProvider('malformedValues')]
    public function testItRefusesAValueItCannotDecode(string $value): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            $value,
            $this->context,
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedValues(): array
    {
        $encoder = new LdapEncoder();

        return [
            'not a sequence' => [$encoder->encode(Asn1::set())],
            'not BER' => ["\x01\x02\x03"],
            'empty' => [''],
            'a field it does not recognize' => [$encoder->encode(Asn1::sequence(
                Asn1::context(
                    2,
                    Asn1::octetString('newpass'),
                ),
                Asn1::context(
                    3,
                    Asn1::octetString('extension'),
                ),
            ))],
        ];
    }

    private static function valueOf(ExtendedRequest $request): string
    {
        $value = $request->toAsn1()->getChild(1)?->getValue();
        self::assertIsString($value);

        return $value;
    }
}
