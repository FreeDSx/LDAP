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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Server\Middleware\ServerControlRegistry;
use PHPUnit\Framework\TestCase;

final class ServerControlRegistryTest extends TestCase
{
    private ServerControlRegistry $subject;

    protected function setUp(): void
    {
        $this->subject = new ServerControlRegistry();
    }

    public function test_search_supports_expected_controls(): void
    {
        self::assertSame(
            [
                Control::OID_PROXY_AUTHORIZATION,
                Control::OID_MANAGE_DSA_IT,
                Control::OID_PWD_POLICY,
                Control::OID_SORTING,
                Control::OID_ASSERTION,
                Control::OID_SUBENTRIES,
            ],
            $this->subject->supportedControlsFor(HandlerId::Search),
        );
    }

    public function test_paging_supports_expected_controls(): void
    {
        self::assertSame(
            [
                Control::OID_PROXY_AUTHORIZATION,
                Control::OID_MANAGE_DSA_IT,
                Control::OID_PWD_POLICY,
                Control::OID_PAGING,
                Control::OID_SORTING,
                Control::OID_ASSERTION,
                Control::OID_SUBENTRIES,
            ],
            $this->subject->supportedControlsFor(HandlerId::Paging),
        );
    }

    public function test_dispatch_supports_expected_controls(): void
    {
        self::assertSame(
            [
                Control::OID_PROXY_AUTHORIZATION,
                Control::OID_MANAGE_DSA_IT,
                Control::OID_PWD_POLICY,
                Control::OID_RELAX_RULES,
                Control::OID_ASSERTION,
                Control::OID_PRE_READ,
                Control::OID_POST_READ,
                Control::OID_SUBTREE_DELETE,
            ],
            $this->subject->supportedControlsFor(HandlerId::Dispatch),
        );
    }

    /**
     * @param HandlerId $id
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('globalOnlyHandlers')]
    public function test_handlers_without_specific_controls_support_only_the_global_set(HandlerId $id): void
    {
        self::assertSame(
            [
                Control::OID_PROXY_AUTHORIZATION,
                Control::OID_MANAGE_DSA_IT,
                Control::OID_PWD_POLICY,
            ],
            $this->subject->supportedControlsFor($id),
        );
    }

    /**
     * @param HandlerId $id
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('checkedHandlers')]
    public function test_the_password_policy_control_is_supported_on_every_checked_handler(HandlerId $id): void
    {
        self::assertContains(
            Control::OID_PWD_POLICY,
            $this->subject->supportedControlsFor($id),
        );
    }

    /**
     * @return iterable<string, array{HandlerId}>
     */
    public static function globalOnlyHandlers(): iterable
    {
        yield 'whoami' => [HandlerId::WhoAmI];
        yield 'password modify' => [HandlerId::PasswordModify];
        yield 'subschema' => [HandlerId::Subschema];
        yield 'root dse' => [HandlerId::RootDse];
        yield 'start tls' => [HandlerId::StartTls];
        yield 'cancel' => [HandlerId::Cancel];
        yield 'unsupported extended' => [HandlerId::UnsupportedExtended];
    }

    public function test_abandon_and_unbind_are_exempt_from_the_check(): void
    {
        self::assertFalse($this->subject->appliesTo(HandlerId::Abandon));
        self::assertFalse($this->subject->appliesTo(HandlerId::Unbind));
    }

    /**
     * @param HandlerId $id
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('checkedHandlers')]
    public function test_non_exempt_handlers_are_subject_to_the_check(HandlerId $id): void
    {
        self::assertTrue($this->subject->appliesTo($id));
    }

    /**
     * @return iterable<string, array{HandlerId}>
     */
    public static function checkedHandlers(): iterable
    {
        yield 'search' => [HandlerId::Search];
        yield 'paging' => [HandlerId::Paging];
        yield 'dispatch' => [HandlerId::Dispatch];
        yield 'whoami' => [HandlerId::WhoAmI];
        yield 'root dse' => [HandlerId::RootDse];
        yield 'cancel' => [HandlerId::Cancel];
        yield 'unsupported extended' => [HandlerId::UnsupportedExtended];
    }
}
