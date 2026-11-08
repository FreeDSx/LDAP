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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use PHPUnit\Framework\TestCase;

final class PasswordModifyResponseTest extends TestCase
{
    private PasswordModifyResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new PasswordModifyResponse(
            new LdapResult(0, 'foo'),
            '12345',
        );
    }

    public function test_it_should_get_the_dn(): void
    {
        self::assertEquals(
            new Dn('foo'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_get_the_generated_password(): void
    {
        self::assertSame(
            '12345',
            $this->subject->getGeneratedPassword(),
        );
    }
}
