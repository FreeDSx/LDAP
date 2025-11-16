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

use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\ResultCode;
use PHPUnit\Framework\TestCase;

final class ReferralExceptionTest extends TestCase
{
    private ReferralException $subject;

    protected function setUp(): void
    {
        $this->subject = new ReferralException(
            'foo',
            new LdapUrl('foo'),
            new LdapUrl('bar'),
        );
    }

    public function test_it_should_get_the_referrals(): void
    {
        self::assertEquals(
            [
                new LdapUrl('foo'),
                new LdapUrl('bar'),
            ],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_set_the_message(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getMessage(),
        );
    }

    public function test_it_should_have_a_code_of_the_referral_result_code(): void
    {
        self::assertSame(
            ResultCode::REFERRAL,
            $this->subject->getCode(),
        );
    }
}
