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
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use PHPUnit\Framework\TestCase;

final class BindResponseTest extends TestCase
{
    private BindResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new BindResponse(
            new LdapResult(
                0,
                'foo',
                'bar',
                new LdapUrl('foo'),
            ),
            'foo',
        );
    }

    public function test_it_should_get_the_sasl_creds(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getSaslCredentials(),
        );
    }

    public function test_it_should_get_the_ldap_result_data(): void
    {
        self::assertSame(
            0,
            $this->subject->getResultCode(),
        );
        self::assertEquals(
            new Dn('foo'),
            $this->subject->getDn(),
        );
        self::assertSame(
            'bar',
            $this->subject->getDiagnosticMessage(),
        );
        self::assertEquals(
            [new LdapUrl('foo')],
            $this->subject->getReferrals(),
        );
    }
}
