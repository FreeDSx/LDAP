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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth\NameResolver;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverChain;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class BindNameResolverChainTest extends TestCase
{
    private ReadBackendInterface&MockObject $mockBackend;

    private BindNameResolverInterface&MockObject $mockResolverA;

    private BindNameResolverInterface&MockObject $mockResolverB;

    protected function setUp(): void
    {
        $this->mockBackend = $this->createMock(ReadBackendInterface::class);
        $this->mockResolverA = $this->createMock(BindNameResolverInterface::class);
        $this->mockResolverB = $this->createMock(BindNameResolverInterface::class);
    }

    public function test_it_returns_the_first_non_null_result(): void
    {
        $entry = new Entry(new Dn('cn=foo,dc=example,dc=com'));

        $this->mockResolverA
            ->method('resolve')
            ->willReturn($entry);

        $this->mockResolverB
            ->expects($this->never())
            ->method('resolve');

        $chain = new BindNameResolverChain([
            $this->mockResolverA,
            $this->mockResolverB,
        ]);

        self::assertSame(
            $entry,
            $chain->resolve(
                'cn=foo,dc=example,dc=com',
                $this->mockBackend,
            ),
        );
    }

    public function test_it_falls_through_to_the_next_resolver_when_null_is_returned(): void
    {
        $entry = new Entry(new Dn('cn=foo,dc=example,dc=com'));

        $this->mockResolverA
            ->method('resolve')
            ->willReturn(null);

        $this->mockResolverB
            ->method('resolve')
            ->willReturn($entry);

        $chain = new BindNameResolverChain([
            $this->mockResolverA,
            $this->mockResolverB,
        ]);

        self::assertSame(
            $entry,
            $chain->resolve(
                'cn=foo,dc=example,dc=com',
                $this->mockBackend,
            ),
        );
    }

    public function test_it_returns_null_when_all_resolvers_return_null(): void
    {
        $this->mockResolverA
            ->method('resolve')
            ->willReturn(null);

        $this->mockResolverB
            ->method('resolve')
            ->willReturn(null);

        $chain = new BindNameResolverChain([
            $this->mockResolverA,
            $this->mockResolverB,
        ]);

        self::assertNull(
            $chain->resolve(
                'cn=foo,dc=example,dc=com',
                $this->mockBackend,
            ),
        );
    }
}
