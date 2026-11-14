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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization\Requirement;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Initialization\Requirement\ManagerPasswordRequirement;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ManagerPasswordRequirementTest extends TestCase
{
    private const HASHED_PASSWORD = '{SHA}aGFzaA==';

    private PasswordHashService&MockObject $hashService;

    private ManagerPasswordRequirement $subject;

    protected function setUp(): void
    {
        $this->hashService = $this->createMock(PasswordHashService::class);
        $this->subject = new ManagerPasswordRequirement(
            new ManagerIdentity(
                new Dn('cn=manager'),
                self::HASHED_PASSWORD,
            ),
            $this->hashService,
        );
    }

    public function test_a_manager_password_a_bind_could_verify_is_met(): void
    {
        $this->hashService
            ->expects(self::once())
            ->method('assertVerifiable')
            ->with(self::HASHED_PASSWORD);

        $this->subject->assertMet();
    }

    public function test_a_manager_password_no_bind_could_verify_is_refused_with_why(): void
    {
        $this->hashService
            ->method('assertVerifiable')
            ->willThrowException(new InvalidArgumentException('The "{SHA}" password scheme is not supported.'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'The manager password can never be verified. The "{SHA}" password scheme is not supported.',
        );

        $this->subject->assertMet();
    }

    public function test_a_server_without_a_manager_is_met(): void
    {
        $this->hashService
            ->expects(self::never())
            ->method('assertVerifiable');

        (new ManagerPasswordRequirement(
            null,
            $this->hashService,
        ))->assertMet();
    }
}
