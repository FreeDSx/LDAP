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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\MatchedDnFilter;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class MatchedDnFilterTest extends TestCase
{
    private ReadBackendInterface&MockObject $backend;

    private AccessControlInterface&MockObject $accessControl;

    private TokenInterface&MockObject $token;

    private MatchedDnFilter $subject;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->token = $this->createMock(TokenInterface::class);
        $this->subject = new MatchedDnFilter(
            $this->backend,
            $this->accessControl,
        );
    }

    public function test_no_matched_dn_stays_none(): void
    {
        self::assertNull($this->subject->filter(
            null,
            $this->token,
        ));
    }

    public function test_a_matched_dn_the_token_may_see_is_kept(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(new Entry('ou=people,dc=foo,dc=bar'));
        $this->accessControl
            ->method('isEntryVisible')
            ->willReturn(true);

        self::assertSame(
            'ou=people,dc=foo,dc=bar',
            $this->subject->filter(
                new Dn('ou=people,dc=foo,dc=bar'),
                $this->token,
            )?->toString(),
        );
    }

    public function test_a_matched_dn_the_token_may_not_see_is_emptied(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(new Entry('ou=people,dc=foo,dc=bar'));
        $this->accessControl
            ->method('isEntryVisible')
            ->willReturn(false);

        self::assertSame(
            '',
            $this->subject->filter(
                new Dn('ou=people,dc=foo,dc=bar'),
                $this->token,
            )?->toString(),
        );
    }

    public function test_a_matched_dn_naming_no_entry_is_emptied(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(null);

        self::assertSame(
            '',
            $this->subject->filter(
                new Dn('ou=people,dc=foo,dc=bar'),
                $this->token,
            )?->toString(),
        );
    }

    public function test_a_matched_dn_whose_entry_cannot_be_read_is_emptied(): void
    {
        $this->backend
            ->method('get')
            ->willThrowException(new OperationException(
                'The entry cannot be read.',
                ResultCode::OTHER,
            ));

        self::assertSame(
            '',
            $this->subject->filter(
                new Dn('ou=people,dc=foo,dc=bar'),
                $this->token,
            )?->toString(),
        );
    }
}
