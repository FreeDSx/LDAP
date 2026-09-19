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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\ImmediateWriterQueue;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ImmediateWriterQueueTest extends TestCase
{
    private ImmediateWriterQueue $subject;

    protected function setUp(): void
    {
        $this->subject = new ImmediateWriterQueue();
    }

    public function test_it_runs_the_job_on_the_caller(): void
    {
        $ran = false;

        $this->subject->run(static function () use (&$ran): void {
            $ran = true;
        });

        self::assertTrue($ran);
    }

    public function test_a_job_failure_reaches_the_caller(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('boom');

        $this->subject->run(static function (): void {
            throw new RuntimeException('boom');
        });
    }

    public function test_the_caller_is_never_the_writer_even_inside_a_job(): void
    {
        $isWriter = null;

        $this->subject->run(function () use (&$isWriter): void {
            $isWriter = $this->subject->isWriter();
        });

        self::assertFalse($isWriter);
    }
}
