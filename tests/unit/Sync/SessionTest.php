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

namespace Tests\Unit\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Sync\Session;
use PHPUnit\Framework\TestCase;

final class SessionTest extends TestCase
{
    private Session $subject;

    protected function setUp(): void
    {
        $this->subject = new Session(
            Session::MODE_POLL,
            null
        );
    }

    public function test_it_should_get_the_phase_when_it_is_not_set(): void
    {
        self::assertNull($this->subject->getPhase());
    }

    public function test_it_should_get_the_phase_when_it_is_set(): void
    {
        $this->subject->updatePhase(Session::PHASE_DELETE);

        self::assertSame(
            Session::PHASE_DELETE,
            $this->subject->getPhase(),
        );
    }

    public function test_it_should_get_the_cookie_when_it_is_not_set(): void
    {
        self::assertNull($this->subject->getCookie());
    }

    public function test_it_should_get_the_cookie_when_it_is_set(): void
    {
        $this->subject->updateCookie('foo');

        self::assertSame(
            'foo',
            $this->subject->getCookie(),
        );
    }
}
