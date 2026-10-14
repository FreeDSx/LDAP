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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Validation\Check;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\Check\NamingAttributesCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class NamingAttributesCheckTest extends TestCase
{
    private Schema $schema;

    private NamingAttributesCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new NamingAttributesCheck($this->schema);
    }

    #[DataProvider('unmatchableNamingAttributeProvider')]
    public function test_add_named_by_a_type_with_no_equality_rule_reports_a_naming_violation(string $dn): void
    {
        self::assertEquals(
            [self::unmatchableJpegPhoto()],
            $this->check(SchemaWrite::add($this->personEntry($dn))),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unmatchableNamingAttributeProvider(): iterable
    {
        yield 'single valued rdn' => [
            'jpegPhoto=zz,dc=example,dc=com',
        ];
        // Every component of a multi-valued RDN names the entry, so one unmatchable component is enough.
        yield 'multi valued rdn, unmatchable component second' => [
            'cn=Alice+jpegPhoto=zz,dc=example,dc=com',
        ];
        yield 'multi valued rdn, unmatchable component first' => [
            'jpegPhoto=zz+cn=Alice,dc=example,dc=com',
        ];
    }

    public function test_add_named_by_a_type_inheriting_its_equality_rule_passes(): void
    {
        // cn declares no EQUALITY of its own and inherits one from name through SUP.
        self::assertSame(
            [],
            $this->check(SchemaWrite::add($this->personEntry('cn=Alice,dc=example,dc=com'))),
        );
    }

    public function test_add_below_an_ancestor_named_by_an_unmatchable_type_passes(): void
    {
        // Only the leftmost RDN names this entry; the ancestor was its own add's problem.
        self::assertSame(
            [],
            $this->check(SchemaWrite::add($this->personEntry('cn=Alice,jpegPhoto=zz,dc=example,dc=com'))),
        );
    }

    public function test_rename_onto_a_type_with_no_equality_rule_reports_a_naming_violation(): void
    {
        self::assertEquals(
            [self::unmatchableJpegPhoto()],
            $this->check(SchemaWrite::modifyDn($this->personEntry('jpegPhoto=zz,dc=example,dc=com'))),
        );
    }

    public function test_a_modify_is_not_checked(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::modify(
                $this->personEntry('jpegPhoto=zz,dc=example,dc=com'),
                [],
            )),
        );
    }

    public function test_the_root_dse_is_not_checked(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::add(new Entry(new Dn('')))),
        );
    }

    /**
     * @return list<RuleViolation>
     */
    private function check(SchemaWrite $write): array
    {
        return $this->subject->check(
            $write,
            ObjectClassChain::forEntry(
                $this->schema,
                $write->entry,
            ),
        );
    }

    private function personEntry(string $dn): Entry
    {
        return new Entry(
            new Dn($dn),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
    }

    private static function unmatchableJpegPhoto(): RuleViolation
    {
        return new RuleViolation(
            SchemaRule::NamingAttributes,
            ResultCode::NAMING_VIOLATION,
            'Attribute "jpegPhoto" has no equality matching rule and cannot name an entry.',
        );
    }
}
