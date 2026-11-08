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

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use PHPUnit\Framework\TestCase;

final class ExtendedResponseTest extends TestCase
{
    private ExtendedResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new ExtendedResponse(
            new LdapResult(
                0,
                'dc=foo,dc=bar',
                'foo',
            ),
            'foo',
            'bar',
        );
    }

    public function test_it_should_get_the_name(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getName(),
        );
    }

    public function test_it_should_get_the_value(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getValue(),
        );
    }
}
