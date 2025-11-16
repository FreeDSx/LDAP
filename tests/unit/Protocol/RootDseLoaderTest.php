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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class RootDseLoaderTest extends TestCase
{
    private RootDseLoader $subject;

    private LdapClient&MockObject $mockLdapClient;

    protected function setUp(): void
    {
        $this->mockLdapClient = $this->createMock(LdapClient::class);

        $this->subject = new RootDseLoader($this->mockLdapClient);;
    }

    public function test_it_should_load_the_root_dse(): void
    {
        $entry = Entry::fromArray('', []);

        $this->mockLdapClient
            ->expects(self::once())
            ->method('read')
            ->willReturn($entry);

        self::assertSame(
            $entry,
            $this->subject->load(),
        );
    }

    public function test_it_should_use_the_cached_root_dse_on_a_second_load_call(): void
    {
        $entry = Entry::fromArray('', []);

        $this->mockLdapClient
            ->expects(self::once())
            ->method('read')
            ->with('', $this->anything())
            ->willReturn($entry);

        self::assertSame(
            $entry,
            $this->subject->load(),
        );
    }

    public function test_it_should_not_use_the_cached_root_if_the_reload_param_is_used(): void
    {
        $entry = Entry::fromArray('', []);

        $this->mockLdapClient
            ->expects(self::atMost(2))
            ->method('read')
            ->with('', $this->anything())
            ->willReturn($entry);

        $this->subject->load();

        self::assertSame(
            $entry,
            $this->subject->load(reload: true),
        );
    }

    public function test_it_should_throw_an_exception_if_no_root_dse_is_returned(): void
    {
        self::expectException(OperationException::class);

        $this->subject->load();
    }
}
