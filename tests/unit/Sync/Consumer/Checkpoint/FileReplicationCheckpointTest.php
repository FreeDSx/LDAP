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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Consumer\Checkpoint;

use FreeDSx\Ldap\Sync\Consumer\Checkpoint\FileReplicationCheckpoint;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\ReplicationCheckpointInterface;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class FileReplicationCheckpointTest extends TestCase
{
    private string $path;

    private ReplicationCheckpointInterface $subject;

    protected function setUp(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'freedsx_ckpt')
            ?: throw new RuntimeException('Unable to create a temp file.');
        // tempnam creates the file; start the test with no checkpoint present.
        unlink($file);

        $this->path = $file;
        $this->subject = new FileReplicationCheckpoint($this->path);
    }

    protected function tearDown(): void
    {
        foreach ([$this->path, $this->path . '.tmp'] as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }

    public function test_read_returns_null_when_no_checkpoint_exists(): void
    {
        self::assertNull($this->subject->read());
    }

    public function test_write_then_read_round_trips_the_cookie(): void
    {
        $this->subject->write('cookie-123');

        self::assertSame(
            'cookie-123',
            $this->subject->read(),
        );
    }

    public function test_write_replaces_a_previous_checkpoint(): void
    {
        $this->subject->write('first');
        $this->subject->write('second');

        self::assertSame(
            'second',
            $this->subject->read(),
        );
    }

    public function test_a_binary_cookie_round_trips(): void
    {
        $cookie = "rid=001,csn=\x00\x01\xff\x7f";

        $this->subject->write($cookie);

        self::assertSame(
            $cookie,
            $this->subject->read(),
        );
    }

    public function test_write_leaves_no_temp_file_behind(): void
    {
        $this->subject->write('cookie');

        self::assertFileDoesNotExist($this->path . '.tmp');
    }

    public function test_clear_removes_the_checkpoint(): void
    {
        $this->subject->write('cookie');

        $this->subject->clear();

        self::assertNull($this->subject->read());
        self::assertFileDoesNotExist($this->path);
    }

    public function test_clear_without_a_checkpoint_leaves_none(): void
    {
        $this->subject->clear();

        self::assertNull($this->subject->read());
    }
}
