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

namespace spec\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Sync\Session;
use PhpSpec\ObjectBehavior;

class SessionSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(
            Session::MODE_POLL,
            null
        );
    }

    public function it_should_get_the_phase_when_it_is_not_set(): void
    {
        $this->getPhase()
            ->shouldBeNull();
    }

    public function it_should_get_the_phase_when_it_is_set(): void
    {
        $this->updatePhase(Session::PHASE_DELETE);

        $this->getPhase()
            ->shouldBeEqualTo(Session::PHASE_DELETE);
    }

    public function it_should_get_the_cookie_when_it_is_not_set(): void
    {
        $this->getCookie()
            ->shouldBeNull();
    }

    public function it_should_get_the_cookie_when_it_is_set(): void
    {
        $this->updateCookie('foo');

        $this->getCookie()
            ->shouldBeEqualTo('foo');
    }
}
