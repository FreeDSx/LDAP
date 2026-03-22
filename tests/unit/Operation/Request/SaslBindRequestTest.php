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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use PHPUnit\Framework\TestCase;

final class SaslBindRequestTest extends TestCase
{
    public function test_bind_request_returns_sasl_bind_request_from_asn1_with_mechanism_only(): void
    {
        $request = new SaslBindRequest('PLAIN');

        /** @var SaslBindRequest $result */
        $result = BindRequest::fromAsn1($request->toAsn1());

        self::assertInstanceOf(SaslBindRequest::class, $result);
        self::assertSame('PLAIN', $result->getMechanism());
        self::assertNull($result->getCredentials());
    }

    public function test_bind_request_returns_sasl_bind_request_from_asn1_with_mechanism_and_credentials(): void
    {
        $request = new SaslBindRequest(
            'PLAIN',
            "\x00user\x00pass"
        );

        /** @var SaslBindRequest $result */
        $result = BindRequest::fromAsn1($request->toAsn1());

        self::assertInstanceOf(SaslBindRequest::class, $result);
        self::assertSame(
            'PLAIN',
            $result->getMechanism()
        );
        self::assertSame(
            "\x00user\x00pass",
            $result->getCredentials()
        );
    }

    public function test_sasl_bind_request_throws_a_protocol_exception_for_a_malformed_sasl_mechanism(): void
    {
        // Build just the SaslCredentials [3] context part with a non-OctetString as the mechanism.
        $malformedAuth = Asn1::context(
            tagNumber: 3,
            type: Asn1::sequence(
                Asn1::integer(99),  // mechanism must be an OctetString, not an integer
            ),
        );

        self::expectException(ProtocolException::class);

        SaslBindRequest::fromAsn1($malformedAuth);
    }

    public function test_sasl_bind_request_throws_when_the_mechanism_is_empty(): void
    {
        self::expectException(BindException::class);

        (new SaslBindRequest(''))->toAsn1();
    }

    public function test_it_can_change_the_mechanism(): void
    {
        $request = new SaslBindRequest('PLAIN');
        $result = $request->setMechanism('GSSAPI');

        self::assertSame($request, $result);
        self::assertSame('GSSAPI', $request->getMechanism());
    }

    public function test_it_returns_options_set_via_constructor(): void
    {
        $request = new SaslBindRequest('PLAIN', null, ['foo' => 'bar']);

        self::assertSame(['foo' => 'bar'], $request->getOptions());
    }

    public function test_bind_request_throws_for_an_unsupported_authentication_tag(): void
    {
        // Tag 1 and 2 are reserved in the AuthenticationChoice — only 0 (simple/anon) and 3 (SASL) are valid.
        $request = Asn1::application(0, Asn1::sequence(
            Asn1::integer(3),
            Asn1::octetString(''),
            Asn1::context(tagNumber: 1, type: Asn1::octetString('')),
        ));

        self::expectException(ProtocolException::class);

        BindRequest::fromAsn1($request);
    }
}
