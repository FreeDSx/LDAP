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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteScope;
use PHPUnit\Framework\TestCase;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class WriteScopeTest extends TestCase
{
    use RequiresExtensionsTrait;

    private WriteScope $subject;

    protected function setUp(): void
    {
        $this->requireSwoole();

        $this->subject = new WriteScope();
    }

    public function test_it_is_inactive_before_entering(): void
    {
        self::assertFalse($this->subject->isActive());
    }

    public function test_it_is_inactive_after_leaving(): void
    {
        $this->subject->enter();
        $this->subject->leave();

        self::assertFalse($this->subject->isActive());
    }

    public function test_it_is_active_on_the_coroutine_that_entered_it(): void
    {
        $observed = null;

        Coroutine\run(function () use (&$observed): void {
            $this->subject->enter();
            $observed = $this->subject->isActive();
            $this->subject->leave();
        });

        self::assertTrue($observed);
    }

    public function test_it_is_inactive_on_another_coroutine_while_held(): void
    {
        $observed = null;

        Coroutine\run(function () use (&$observed): void {
            $entered = new Channel(1);
            $checked = new Channel(1);

            Coroutine::create(function () use ($entered, $checked): void {
                $this->subject->enter();
                $entered->push(true);
                $checked->pop();
                $this->subject->leave();
            });

            Coroutine::create(function () use ($entered, $checked, &$observed): void {
                $entered->pop();
                $observed = $this->subject->isActive();
                $checked->push(true);
            });
        });

        self::assertFalse($observed);
    }

    public function test_a_nested_enter_keeps_the_scope_held_until_the_outer_leave(): void
    {
        $observed = [];

        Coroutine\run(function () use (&$observed): void {
            $this->subject->enter();
            $this->subject->enter();
            $this->subject->leave();
            $observed['afterInner'] = $this->subject->isActive();
            $this->subject->leave();
            $observed['afterOuter'] = $this->subject->isActive();
        });

        self::assertTrue($observed['afterInner']);
        self::assertFalse($observed['afterOuter']);
    }
}
