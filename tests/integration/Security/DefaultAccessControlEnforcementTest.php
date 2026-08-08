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

namespace Tests\Integration\FreeDSx\Ldap\Security;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\PrivilegedBypassAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\ManagerToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Storage\BackendFactoryTrait;

/**
 * Composes the real manager authenticator with the bypass-wrapped secure-default ACL, as the server wires them.
 */
final class DefaultAccessControlEnforcementTest extends TestCase
{
    use BackendFactoryTrait;

    private const MANAGER_DN = 'cn=manager';

    private const PASSWORD = '12345';

    private const HASH = '{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ=';

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private const OTHER_DN = 'cn=other,dc=foo,dc=bar';

    private PasswordAuthenticatableInterface $authenticator;

    private AccessControlInterface $accessControl;

    protected function setUp(): void
    {
        $backend = self::makeWritableBackend(new InMemoryStorage([
            Entry::fromArray(
                'dc=foo,dc=bar',
                [
                    'objectClass' => ['domain'],
                    'dc' => ['foo'],
                ],
            ),
            Entry::fromArray(
                self::USER_DN,
                [
                    'objectClass' => ['inetOrgPerson'],
                    'cn' => ['user'],
                    'sn' => ['User'],
                    'userPassword' => [self::HASH],
                ],
            ),
            Entry::fromArray(
                self::OTHER_DN,
                [
                    'objectClass' => ['inetOrgPerson'],
                    'cn' => ['other'],
                    'sn' => ['Other'],
                    'userPassword' => [self::HASH],
                ],
            ),
        ]));

        $this->authenticator = new ManagerAwareAuthenticator(
            new PasswordAuthenticator(
                new DnBindNameResolver(),
                $backend,
            ),
            new ManagerIdentity(
                new Dn(self::MANAGER_DN),
                self::HASH,
            ),
            new PasswordHashService(),
        );
        $this->accessControl = new PrivilegedBypassAccessControl(
            new RuleBasedAccessControl(AclRules::secureDefault()),
        );
    }

    public function test_manager_binds_to_a_privileged_token_that_bypasses_the_credential_acl(): void
    {
        $manager = $this->authenticator->authenticate(
            self::MANAGER_DN,
            self::PASSWORD,
        );
        self::assertInstanceOf(
            ManagerToken::class,
            $manager,
        );

        // The manager may write any user's userPassword despite the secure-default credential restriction.
        $this->accessControl->authorizeAttribute(
            $manager,
            new Dn(self::OTHER_DN),
            'userPassword',
            AttributeAccess::Write,
        );

        $this->addToAssertionCount(1);
    }

    public function test_normal_user_is_bound_by_the_credential_acl(): void
    {
        $user = $this->authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        // Self may write its own password.
        $this->accessControl->authorizeAttribute(
            $user,
            new Dn(self::USER_DN),
            'userPassword',
            AttributeAccess::Write,
        );

        // But not another user's.
        $this->expectException(OperationException::class);
        $this->accessControl->authorizeAttribute(
            $user,
            new Dn(self::OTHER_DN),
            'userPassword',
            AttributeAccess::Write,
        );
    }

    public function test_manager_read_keeps_userPassword_that_a_normal_user_loses(): void
    {
        $manager = $this->authenticator->authenticate(
            self::MANAGER_DN,
            self::PASSWORD,
        );
        $user = $this->normalUser();

        $entry = Entry::fromArray(
            self::OTHER_DN,
            [
                'cn' => ['other'],
                'userPassword' => [self::HASH],
            ],
        );

        self::assertNotNull(
            $this->accessControl->filterEntry($manager, $entry)?->get('userPassword'),
        );
        self::assertNull(
            $this->accessControl->filterEntry($user, $entry)?->get('userPassword'),
        );
    }

    public function test_userPassword_is_write_only_for_self(): void
    {
        $user = $this->normalUser();
        $ownDn = new Dn(self::USER_DN);
        $ownEntry = Entry::fromArray(
            self::USER_DN,
            [
                'cn' => ['user'],
                'userPassword' => [self::HASH],
            ],
        );

        // Self may write its own password.
        $this->accessControl->authorizeAttribute(
            $user,
            $ownDn,
            'userPassword',
            AttributeAccess::Write,
        );

        // But self cannot read it, on search or via Compare.
        self::assertNull(
            $this->accessControl->filterEntry($user, $ownEntry)?->get('userPassword'),
        );

        $this->expectException(OperationException::class);
        $this->accessControl->authorizeAttribute(
            $user,
            $ownDn,
            'userPassword',
            AttributeAccess::Read,
        );
    }

    private function normalUser(): AuthenticatedTokenInterface
    {
        return $this->authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );
    }
}
