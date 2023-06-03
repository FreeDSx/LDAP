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

namespace spec\FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use PhpSpec\ObjectBehavior;

class UnsolicitedNotificationExceptionSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo', 0, null, 'bar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(UnsolicitedNotificationException::class);
    }

    public function it_should_extend_protocol_exception(): void
    {
        $this->shouldBeAnInstanceOf(ProtocolException::class);
    }

    public function it_should_get_the_name_oid(): void
    {
        $this->getOid()->shouldBeEqualTo('bar');
    }
}
