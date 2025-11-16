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

namespace Tests\Unit\FreeDSx\Ldap\Server\Token;

use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class BindTokenTest extends TestCase
{
    private BindToken $subject;

    protected function setUp(): void
    {
        $this->subject = new BindToken(
            'foo',
            'bar',
        );
    }

    public function test_it_should_get_the_username(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_get_the_password(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getPassword(),
        );
    }

    public function test_it_should_get_the_version(): void
    {
        self::assertSame(
            3,
            $this->subject->getVersion(),
        );
    }
}
