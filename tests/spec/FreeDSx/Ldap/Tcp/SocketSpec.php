<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Tcp;

use FreeDSx\Ldap\Tcp\Socket;
use PhpSpec\ObjectBehavior;

class SocketSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(Socket::class);
    }
}
