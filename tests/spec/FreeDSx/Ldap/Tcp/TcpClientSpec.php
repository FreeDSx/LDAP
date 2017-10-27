<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Tcp;

use FreeDSx\Ldap\Tcp\TcpClient;
use PhpSpec\ObjectBehavior;

class TcpClientSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('localhost');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(TcpClient::class);
    }
}
