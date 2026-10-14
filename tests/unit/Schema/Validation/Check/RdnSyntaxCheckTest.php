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
use FreeDSx\Ldap\Schema\Validation\Check\RdnSyntaxCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RdnSyntaxCheckTest extends TestCase
{
    private Schema $schema;

    private RdnSyntaxCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new RdnSyntaxCheck(new AttributeSyntaxResolver($this->schema));
    }

    #[DataProvider('rdnValueFailingItsSyntaxProvider')]
    public function test_add_with_an_rdn_value_failing_its_syntax_reports_invalid_dn_syntax(
        string $dn,
        string $attribute,
    ): void {
        self::assertEquals(
            [self::violationFor($attribute)],
            $this->check(SchemaWrite::add($this->personEntry($dn))),
        );
    }

    #[DataProvider('rdnValueFailingItsSyntaxProvider')]
    public function test_rename_onto_an_rdn_value_failing_its_syntax_reports_invalid_dn_syntax(
        string $dn,
        string $attribute,
    ): void {
        self::assertEquals(
            [self::violationFor($attribute)],
            $this->check(SchemaWrite::modifyDn($this->personEntry($dn))),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function rdnValueFailingItsSyntaxProvider(): iterable
    {
        yield 'an empty directory string' => [
            'cn=,dc=example,dc=com',
            'cn',
        ];
        yield 'a country code of three letters' => [
            'c=USA,dc=example,dc=com',
            'c',
        ];
    }

    public function test_a_conforming_rdn_passes(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::add($this->personEntry('cn=Alice,dc=example,dc=com'))),
        );
    }

    public function test_a_modify_leaves_the_rdn_unchecked(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::modify(
                $this->personEntry('c=USA,dc=example,dc=com'),
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

    private static function violationFor(string $attribute): RuleViolation
    {
        return new RuleViolation(
            SchemaRule::AttributeSyntax,
            ResultCode::INVALID_DN_SYNTAX,
            sprintf(
                'A value of attribute "%s" in the RDN does not conform to its syntax.',
                $attribute,
            ),
        );
    }
}
