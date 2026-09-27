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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Validation;

use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SchemaRuleTest extends TestCase
{
    #[DataProvider('waiverProvider')]
    public function test_each_rule_states_who_may_waive_it(
        SchemaRule $rule,
        bool $byControl,
        bool $byPolicy,
    ): void {
        self::assertSame(
            [$byControl, $byPolicy],
            [$rule->isRelaxableByControl(), $rule->isRelaxableByPolicy()],
        );
    }

    /**
     * @return Generator<string, array{rule: SchemaRule, byControl: bool, byPolicy: bool}>
     */
    public static function waiverProvider(): Generator
    {
        yield 'structural class change' => [
            'rule' => SchemaRule::StructuralClassChange,
            'byControl' => true,
            'byPolicy' => true,
        ];

        yield 'settable operational attribute' => [
            'rule' => SchemaRule::SettableOperationalAttribute,
            'byControl' => true,
            'byPolicy' => true,
        ];

        yield 'no user modification' => [
            'rule' => SchemaRule::NoUserModification,
            'byControl' => false,
            'byPolicy' => true,
        ];

        yield 'structural class' => [
            'rule' => SchemaRule::StructuralClass,
            'byControl' => false,
            'byPolicy' => true,
        ];

        yield 'required attributes' => [
            'rule' => SchemaRule::RequiredAttributes,
            'byControl' => false,
            'byPolicy' => true,
        ];

        yield 'allowed attributes' => [
            'rule' => SchemaRule::AllowedAttributes,
            'byControl' => false,
            'byPolicy' => true,
        ];

        yield 'defined attribute types' => [
            'rule' => SchemaRule::DefinedAttributeTypes,
            'byControl' => false,
            'byPolicy' => true,
        ];

        yield 'single value' => [
            'rule' => SchemaRule::SingleValue,
            'byControl' => false,
            'byPolicy' => true,
        ];

        yield 'naming attributes' => [
            'rule' => SchemaRule::NamingAttributes,
            'byControl' => false,
            'byPolicy' => true,
        ];

        yield 'attribute syntax' => [
            'rule' => SchemaRule::AttributeSyntax,
            'byControl' => false,
            'byPolicy' => false,
        ];

        yield 'value limit' => [
            'rule' => SchemaRule::ValueLimit,
            'byControl' => false,
            'byPolicy' => false,
        ];

        yield 'equivalent values' => [
            'rule' => SchemaRule::EquivalentValues,
            'byControl' => false,
            'byPolicy' => false,
        ];

        yield 'distinct descriptions' => [
            'rule' => SchemaRule::DistinctDescriptions,
            'byControl' => false,
            'byPolicy' => false,
        ];
    }
}
