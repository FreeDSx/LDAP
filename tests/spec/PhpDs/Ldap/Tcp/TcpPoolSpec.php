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

use PhpDs\Ldap\Tcp\TcpPool;
use PhpSpec\ObjectBehavior;

class TcpPoolSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(['servers' => ['foo', 'bar']]);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(TcpPool::class);
    }
}
