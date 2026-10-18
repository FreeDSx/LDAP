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

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\AclRuleIndex;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use PHPUnit\Framework\TestCase;

final class AclRuleIndexTest extends TestCase
{
    private AttributeRule $allowCnRead;

    private AttributeRule $denyAnyRead;

    private AttributeRule $denyCnWrite;

    private AttributeRule $allowMailBoth;

    private OperationRule $allowSearch;

    private OperationRule $denyAll;

    private OperationRule $allowAdd;

    private AclRuleIndex $subject;

    protected function setUp(): void
    {
        $anyone = new AnySubjectMatcher();
        $anywhere = new AnyTargetMatcher();

        $this->allowCnRead = AttributeRule::allow(
            $anyone,
            $anywhere,
            'cn',
        )->forRead();
        $this->denyAnyRead = AttributeRule::deny($anyone)->forRead();
        $this->denyCnWrite = AttributeRule::deny(
            $anyone,
            $anywhere,
            'cn',
        )->forWrite();
        $this->allowMailBoth = AttributeRule::allow(
            $anyone,
            $anywhere,
            'mail',
        );
        $this->allowSearch = OperationRule::allow(
            $anyone,
            $anywhere,
            OperationType::Search,
        );
        $this->denyAll = OperationRule::deny($anyone);
        $this->allowAdd = OperationRule::allow(
            $anyone,
            $anywhere,
            OperationType::Add,
        );

        $this->subject = AclRuleIndex::of(AclRules::fromEmpty(
            operations: [
                $this->allowSearch,
                $this->denyAll,
                $this->allowAdd,
            ],
            attributes: [
                $this->allowCnRead,
                $this->denyAnyRead,
                $this->denyCnWrite,
                $this->allowMailBoth,
            ],
        ));
    }

    public function test_a_named_attribute_holds_its_own_rules_and_those_naming_none_in_configured_order(): void
    {
        self::assertSame(
            [$this->allowCnRead, $this->denyAnyRead],
            $this->subject->attributeRules(
                AttributeAccess::Read,
                'cn',
            ),
        );
    }

    public function test_an_attribute_no_rule_names_holds_only_the_rules_naming_none(): void
    {
        self::assertSame(
            [$this->denyAnyRead],
            $this->subject->attributeRules(
                AttributeAccess::Read,
                'sn',
            ),
        );
    }

    public function test_a_rule_for_both_directions_applies_to_reads_and_writes(): void
    {
        self::assertSame(
            [$this->denyAnyRead, $this->allowMailBoth],
            $this->subject->attributeRules(
                AttributeAccess::Read,
                'mail',
            ),
        );
        self::assertSame(
            [$this->allowMailBoth],
            $this->subject->attributeRules(
                AttributeAccess::Write,
                'mail',
            ),
        );
    }

    public function test_a_write_rule_applies_only_to_writes(): void
    {
        self::assertSame(
            [$this->denyCnWrite],
            $this->subject->attributeRules(
                AttributeAccess::Write,
                'cn',
            ),
        );
    }

    public function test_a_request_for_both_directions_holds_only_rules_for_both(): void
    {
        self::assertSame(
            [$this->allowMailBoth],
            $this->subject->attributeRules(
                AttributeAccess::Both,
                'mail',
            ),
        );
        self::assertSame(
            [],
            $this->subject->attributeRules(
                AttributeAccess::Both,
                'cn',
            ),
        );
    }

    public function test_an_operation_holds_its_own_rules_and_those_naming_none_in_configured_order(): void
    {
        self::assertSame(
            [$this->allowSearch, $this->denyAll],
            $this->subject->operationRules(OperationType::Search),
        );
        self::assertSame(
            [$this->denyAll, $this->allowAdd],
            $this->subject->operationRules(OperationType::Add),
        );
        self::assertSame(
            [$this->denyAll],
            $this->subject->operationRules(OperationType::Delete),
        );
    }

    public function test_a_name_with_only_write_rules_has_no_read_rules(): void
    {
        $subject = AclRuleIndex::of(AclRules::fromEmpty(
            attributes: [$this->denyCnWrite],
        ));

        self::assertSame(
            [],
            $subject->attributeRules(
                AttributeAccess::Read,
                'cn',
            ),
        );
        self::assertSame(
            [$this->denyCnWrite],
            $subject->attributeRules(
                AttributeAccess::Write,
                'cn',
            ),
        );
    }
}
