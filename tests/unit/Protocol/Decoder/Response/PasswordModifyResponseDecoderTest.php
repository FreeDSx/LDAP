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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Response\PasswordModifyResponseDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class PasswordModifyResponseDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private PasswordModifyResponseDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(PasswordModifyResponseDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheGeneratedPasswordAndKeepsTheResult(): void
    {
        self::assertEquals(
            new PasswordModifyResponse(
                new LdapResult(
                    0,
                    'dc=foo,dc=bar',
                    'foo',
                    new LdapUrl('foo'),
                ),
                'bleep-blorp',
            ),
            $this->subject->decode(
                new ExtendedResponse(
                    new LdapResult(
                        0,
                        'dc=foo,dc=bar',
                        'foo',
                        new LdapUrl('foo'),
                    ),
                    ExtendedRequest::OID_PWD_MODIFY,
                    (new LdapEncoder())->encode(Asn1::sequence(Asn1::context(
                        0,
                        Asn1::octetString('bleep-blorp'),
                    ))),
                ),
                $this->context,
            ),
        );
    }

    public function testItDecodesAResponseWithNoGeneratedPassword(): void
    {
        self::assertNull($this->subject->decode(
            new ExtendedResponse(
                new LdapResult(0),
                null,
                (new LdapEncoder())->encode(Asn1::sequence()),
            ),
            $this->context,
        )->getGeneratedPassword());
    }

    public function testItDecodesAResponseWithNoValue(): void
    {
        self::assertNull($this->subject->decode(
            new ExtendedResponse(new LdapResult(0)),
            $this->context,
        )->getGeneratedPassword());
    }

    public function testItRefusesAnEmptyValueAsMalformed(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The data to decode cannot be empty.');

        $this->subject->decode(
            new ExtendedResponse(
                new LdapResult(0),
                null,
                '',
            ),
            $this->context,
        );
    }
}
