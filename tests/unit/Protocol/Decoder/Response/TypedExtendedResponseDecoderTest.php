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

use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Response\TypedExtendedResponseDecoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class TypedExtendedResponseDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private TypedExtendedResponseDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(TypedExtendedResponseDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItKnowsWhichRequestsHaveATypedResponse(): void
    {
        self::assertSame(
            [true, false],
            [
                $this->subject->has(ExtendedRequest::OID_PWD_MODIFY),
                $this->subject->has('foo'),
            ],
        );
    }

    public function testItDecodesTheTypedResponseForTheRequestItAnswers(): void
    {
        self::assertInstanceOf(
            PasswordModifyResponse::class,
            $this->subject->decode(
                new ExtendedResponse(new LdapResult(0)),
                ExtendedRequest::OID_PWD_MODIFY,
                $this->context,
            ),
        );
    }

    public function testItRefusesARequestWithNoTypedResponse(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('There is no extended response mapped for foo.');

        $this->subject->decode(
            new ExtendedResponse(new LdapResult(0)),
            'foo',
            $this->context,
        );
    }
}
