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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Request\ModifyDnRequestDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ModifyDnRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private ModifyDnRequestDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(ModifyDnRequestDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesARenameWithANewSuperior(): void
    {
        $request = new ModifyDnRequest(
            'foo',
            'cn=bar',
            false,
            'foobar',
        );

        self::assertEquals(
            $request,
            $this->subject->decode(
                $request->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItDecodesARenameWithoutANewSuperior(): void
    {
        $request = new ModifyDnRequest(
            'foo',
            'cn=bar',
            false,
        );

        self::assertEquals(
            $request,
            $this->subject->decode(
                $request->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItCompletesANewSuperiorReceivedUndecoded(): void
    {
        $encoder = new LdapEncoder();
        $request = new ModifyDnRequest(
            'foo',
            'cn=bar',
            true,
            'ou=people,dc=bar',
        );

        self::assertEquals(
            $request,
            $this->subject->decode(
                $encoder->decode($encoder->encode($request->toAsn1())),
                $this->context,
            ),
        );
    }

    public function testItIgnoresATrailingComponentAfterTheNewSuperior(): void
    {
        $request = new ModifyDnRequest(
            'foo',
            'cn=bar',
            false,
            'foobar',
        );

        self::assertEquals(
            $request,
            $this->subject->decode(
                self::withTrailingComponent($request->toAsn1()),
                $this->context,
            ),
        );
    }

    public function testItDoesNotMistakeATrailingComponentForANewSuperior(): void
    {
        $request = new ModifyDnRequest(
            'foo',
            'cn=bar',
            false,
        );

        self::assertEquals(
            $request,
            $this->subject->decode(
                self::withTrailingComponent($request->toAsn1()),
                $this->context,
            ),
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedRequests')]
    public function testItRefusesAMalformedRequest(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            $type,
            $this->context,
        );
    }

    /**
     * @return array<string, array{AbstractType<mixed>}>
     */
    public static function malformedRequests(): array
    {
        return [
            'not a sequence' => [Asn1::octetString('foo')],
            'too few components' => [Asn1::sequence(Asn1::integer(1))],
        ];
    }
}
