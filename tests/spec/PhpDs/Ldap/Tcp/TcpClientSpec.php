<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Tcp;

use PhpDs\Ldap\Tcp\TcpClient;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

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
