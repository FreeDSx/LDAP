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

namespace Tests\Unit\FreeDSx\Ldap\Server\Resources;

use FreeDSx\Ldap\Server\Resources\OpenFileLimit;
use PHPUnit\Framework\TestCase;

final class OpenFileLimitTest extends TestCase
{
    private OpenFileLimit $subject;

    protected function setUp(): void
    {
        $this->subject = new OpenFileLimit(1024);
    }

    public function test_it_is_reached_before_a_connection_limit_that_leaves_too_few_spare_descriptors(): void
    {
        self::assertTrue($this->subject->isReachedBefore(
            1024,
            1,
        ));
        self::assertTrue($this->subject->isReachedBefore(
            961,
            1,
        ));
    }

    public function test_it_is_not_reached_before_a_connection_limit_that_leaves_enough_spare_descriptors(): void
    {
        self::assertFalse($this->subject->isReachedBefore(
            960,
            1,
        ));
    }

    public function test_each_client_counts_every_descriptor_it_holds(): void
    {
        self::assertTrue($this->subject->isReachedBefore(
            321,
            3,
        ));
        self::assertFalse($this->subject->isReachedBefore(
            320,
            3,
        ));
    }

    public function test_it_is_reached_first_when_connections_are_unlimited(): void
    {
        self::assertTrue($this->subject->isReachedBefore(
            0,
            1,
        ));
    }

    public function test_an_unlimited_open_file_limit_is_never_reached_first(): void
    {
        $unlimited = new OpenFileLimit(null);

        self::assertFalse($unlimited->isReachedBefore(
            0,
            1,
        ));
        self::assertFalse($unlimited->isReachedBefore(
            1024,
            3,
        ));
    }
}
