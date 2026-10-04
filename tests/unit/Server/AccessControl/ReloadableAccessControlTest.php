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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\BackendAwareInterface;
use FreeDSx\Ldap\Server\AccessControl\ReloadableAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class ReloadableAccessControlTest extends TestCase
{
    private const OID = '1.2.3.4';

    private ReloadableAccessControl $subject;

    protected function setUp(): void
    {
        $this->subject = new ReloadableAccessControl(new RuleBasedAccessControl(AclRules::fromEmpty(
            extendedOps: [ExtendedOperationRule::allow(Subject::anyone(), self::OID)],
        )));
    }

    public function test_decisions_come_from_the_installed_policy(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->authorizeExtendedOperation(
            BindToken::fromDn('cn=user,dc=foo,dc=bar'),
            self::OID,
        );
    }

    public function test_decisions_after_a_replace_come_from_the_new_policy(): void
    {
        $this->subject->replace(new RuleBasedAccessControl(AclRules::fromEmpty()));

        $this->expectException(OperationException::class);

        $this->subject->authorizeExtendedOperation(
            BindToken::fromDn('cn=user,dc=foo,dc=bar'),
            self::OID,
        );
    }

    public function test_a_replacing_policy_receives_the_backend_set_earlier(): void
    {
        $backend = $this->createMock(ReadBackendInterface::class);
        $replacement = $this->createMockForIntersectionOfInterfaces([
            AccessControlInterface::class,
            BackendAwareInterface::class,
        ]);
        $replacement
            ->expects(self::once())
            ->method('setBackend')
            ->with($backend);

        $this->subject->setBackend($backend);
        $this->subject->replace($replacement);
    }

    public function test_the_backend_is_passed_to_the_installed_policy(): void
    {
        $backend = $this->createMock(ReadBackendInterface::class);
        $installed = $this->createMockForIntersectionOfInterfaces([
            AccessControlInterface::class,
            BackendAwareInterface::class,
        ]);
        $installed
            ->expects(self::once())
            ->method('setBackend')
            ->with($backend);
        $subject = new ReloadableAccessControl($installed);

        $subject->setBackend($backend);
    }
}
