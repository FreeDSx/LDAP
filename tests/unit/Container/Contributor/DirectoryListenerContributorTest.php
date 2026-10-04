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

namespace Tests\Unit\FreeDSx\Ldap\Container\Contributor;

use FreeDSx\Ldap\Container\Contributor\DirectoryListenerContributor;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\AccessControl\AclRuleNames;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\ReloadableAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\Backend\NonResettable;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class DirectoryListenerContributorTest extends TestCase
{
    private const OID = '1.2.3.4';

    private ServerOptions $options;

    private ReloadableAccessControl $accessControl;

    private DirectoryListenerContributor $subject;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults();
        $this->accessControl = new ReloadableAccessControl(new RuleBasedAccessControl(AclRules::fromEmpty()));

        $this->subject = new DirectoryListenerContributor(
            new NonResettable(),
            [],
            $this->options->getStorageConfig(),
            $this->accessControl,
            new AclRuleNames($this->options->getSchema()),
        );
    }

    public function test_a_reloaded_access_policy_replaces_the_one_open_connections_decide_with(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->applyReload((clone $this->options)->setAclRules(AclRules::fromEmpty(
            extendedOps: [ExtendedOperationRule::allow(Subject::anyone(), self::OID)],
        )));

        $this->accessControl->authorizeExtendedOperation(
            BindToken::fromDn('cn=user,dc=foo,dc=bar'),
            self::OID,
        );
    }

    public function test_the_policy_in_place_holds_until_a_reload_is_applied(): void
    {
        $this->expectException(OperationException::class);

        $this->accessControl->authorizeExtendedOperation(
            BindToken::fromDn('cn=user,dc=foo,dc=bar'),
            self::OID,
        );
    }
}
