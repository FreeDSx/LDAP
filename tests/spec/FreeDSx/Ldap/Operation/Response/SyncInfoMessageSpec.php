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

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class SyncInfoMessageSpec extends ObjectBehavior
{
    public function let(): void
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::application(25, Asn1::sequence(
            Asn1::context(0, Asn1::octetString(IntermediateResponse::OID_SYNC_INFO)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::context(3, Asn1::sequence(
                Asn1::octetString('omnomnom'),
                Asn1::boolean(false),
                Asn1::setOf(Asn1::octetString('foo'), Asn1::octetString('bar'))
            )))))
        ))]);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SyncInfoMessage::class);
    }
}
