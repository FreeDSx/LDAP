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

use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\TestCase;

final class AnonTokenTest extends TestCase
{
    private AnonToken $subject;

    protected function setUp(): void
    {
        $this->subject = new AnonToken('foo');
    }

    public function test_it_should_get_the_username(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_get_a_null_password(): void
    {
        self::assertNull($this->subject->getPassword());;
    }

    public function test_it_should_get_the_version(): void
    {
        self::assertSame(
            3,
            $this->subject->getVersion(),
        );
    }
}
