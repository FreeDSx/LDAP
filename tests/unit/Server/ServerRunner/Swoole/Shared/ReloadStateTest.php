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

namespace Tests\Unit\FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared;

use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ReloadState;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class ReloadStateTest extends TestCase
{
    use RequiresExtensionsTrait;

    private ReloadState $subject;

    protected function setUp(): void
    {
        $this->requireSwoole();

        $this->subject = new ReloadState();
    }

    public function test_a_server_that_never_reloaded_reports_so(): void
    {
        self::assertFalse($this->subject->hasReloaded());
    }

    public function test_a_marked_reload_is_reported(): void
    {
        $this->subject->markReloaded();

        self::assertTrue($this->subject->hasReloaded());
    }
}
