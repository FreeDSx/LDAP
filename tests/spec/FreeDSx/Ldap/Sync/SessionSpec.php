<?php

declare(strict_types=1);

namespace spec\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Sync\Session;
use PhpSpec\ObjectBehavior;

class SessionSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(
            Session::STAGE_REFRESH,
            null
        );
    }

    public function it_should_get_if_it_is_refreshing(): void
    {
        $this->isRefreshing()
            ->shouldBeEqualTo(true);
    }

    public function it_should_get_if_it_is_persisting(): void
    {
        $this->updateStage(Session::STAGE_PERSIST);

        $this->isPersisting()
            ->shouldBeEqualTo(true);
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
