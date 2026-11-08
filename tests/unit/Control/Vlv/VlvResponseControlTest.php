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

namespace Tests\Unit\FreeDSx\Ldap\Control\Vlv;

use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use PHPUnit\Framework\TestCase;

class VlvResponseControlTest extends TestCase
{
    private VlvResponseControl $subject;

    protected function setUp(): void
    {
        $this->subject = new VlvResponseControl(
            offset: 10,
            count: 9,
            result: 0,
        );
    }

    public function test_it_should_get_the_offset(): void
    {
        self::assertSame(
            10,
            $this->subject->getOffset(),
        );
    }

    public function test_it_should_get_the_count(): void
    {
        self::assertSame(
            9,
            $this->subject->getCount(),
        );
    }

    public function test_it_should_get_the_context_id(): void
    {
        self::assertNull($this->subject->getContextId());
    }

    public function test_it_should_get_the_result(): void
    {
        self::assertSame(
            0,
            $this->subject->getResult(),
        );
    }
}
