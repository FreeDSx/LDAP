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

namespace Tests\Unit\FreeDSx\Ldap\Operation;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\LdapResult;
use PHPUnit\Framework\TestCase;

final class LdapResultTest extends TestCase
{
    private LdapResult $subject;

    protected function setUp(): void
    {
        $this->subject = new LdapResult(
            0,
            'foo',
            'bar',
        );
    }

    public function test_it_should_get_the_diagnostic_message(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getDiagnosticMessage(),
        );
    }

    public function test_it_should_get_the_result_code(): void
    {
        self::assertSame(
            0,
            $this->subject->getResultCode(),
        );
    }

    public function test_it_should_get_the_dn(): void
    {
        self::assertEquals(
            new Dn('foo'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_get_the_referrals(): void
    {
        self::assertEmpty($this->subject->getReferrals());
    }
}
