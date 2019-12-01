<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Queue\MessageWrapper;

use FreeDSx\Ldap\Protocol\Queue\MessageWrapper\SaslMessageWrapper;
use PhpSpec\ObjectBehavior;

class SaslMessageWrapperSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(SaslMessageWrapper::class);
    }
}