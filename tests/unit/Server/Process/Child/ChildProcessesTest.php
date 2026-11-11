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

namespace Tests\Unit\FreeDSx\Ldap\Server\Process\Child;

use FreeDSx\Ldap\Server\Process\Child\ChildProcess;
use FreeDSx\Ldap\Server\Process\Child\ChildProcesses;
use PHPUnit\Framework\TestCase;

final class ChildProcessesTest extends TestCase
{
    private ChildProcesses $subject;

    protected function setUp(): void
    {
        $this->subject = new ChildProcesses();
    }

    public function test_a_fork_forgets_the_children_it_inherited(): void
    {
        $this->subject->add(new ChildProcess(1));

        $this->subject->releaseInherited();

        self::assertCount(
            0,
            $this->subject,
        );
    }
}
