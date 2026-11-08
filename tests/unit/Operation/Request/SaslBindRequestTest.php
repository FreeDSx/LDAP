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

use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Sasl\Options\DigestMD5Options;
use PHPUnit\Framework\TestCase;

final class SaslBindRequestTest extends TestCase
{
    /**
     * RFC 4511 4.2.1 uses an empty mechanism to abort a negotiation, so a client has to be able to send one.
     */
    public function test_an_empty_mechanism_can_be_encoded(): void
    {
        $request = new SaslBindRequest('');
        $request->toAsn1();

        self::assertSame(
            '',
            $request->getMechanism(),
        );
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
        $options = new DigestMD5Options();
        $request = new SaslBindRequest('PLAIN', null, $options);

        self::assertSame($options, $request->getOptions());
    }
}
