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
use FreeDSx\Ldap\Schema\Validation\Check\DistinctDescriptionsCheck;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use PHPUnit\Framework\TestCase;

final class DistinctDescriptionsCheckTest extends TestCase
{
    private Schema $schema;

    private DistinctDescriptionsCheck $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new DistinctDescriptionsCheck();
    }

    public function test_add_rejects_duplicate_attribute_descriptions(): void
    {
        self::assertEquals(
            [
                new RuleViolation(
                    SchemaRule::DistinctDescriptions,
                    ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                    'Attribute "CN" is supplied more than once.',
                ),
            ],
            $this->check(SchemaWrite::add($this->entryNamingCnTwice())),
        );
    }

    public function test_an_add_with_distinct_descriptions_passes(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );

        self::assertSame(
            [],
            $this->check(SchemaWrite::add($entry)),
        );
    }

    public function test_a_modify_is_not_checked(): void
    {
        self::assertSame(
            [],
            $this->check(SchemaWrite::modify(
                $this->entryNamingCnTwice(),
                [],
            )),
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

    private function entryNamingCnTwice(): Entry
    {
        return new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('CN', 'Other'),
            new Attribute('sn', 'Smith'),
        );
    }
}
