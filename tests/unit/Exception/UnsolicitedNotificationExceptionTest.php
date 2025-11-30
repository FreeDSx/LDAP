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

namespace Tests\Unit\FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use PHPUnit\Framework\TestCase;

final class UnsolicitedNotificationExceptionTest extends TestCase
{
    private UnsolicitedNotificationException $subject;

    protected function setUp(): void
    {
        $this->subject = new UnsolicitedNotificationException(
            'foo',
            0,
            null,
            'bar',
        );
    }

    public function test_it_should_get_the_name_oid(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getOid(),
        );
    }
}
