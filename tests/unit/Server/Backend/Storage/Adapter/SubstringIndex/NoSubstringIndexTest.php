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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\NoSubstringIndex;
use PHPUnit\Framework\TestCase;

final class NoSubstringIndexTest extends TestCase
{
    private NoSubstringIndex $subject;

    protected function setUp(): void
    {
        $this->subject = new NoSubstringIndex();
    }

    public function test_it_adds_no_schema(): void
    {
        self::assertSame(
            [],
            $this->subject->schemaStatements(new SqliteDialect()),
        );
    }

    public function test_it_indexes_no_attribute(): void
    {
        self::assertFalse($this->subject->indexes('cn'));
    }

    public function test_it_reads_no_original_value(): void
    {
        self::assertFalse($this->subject->readsOriginalValue('cn'));
    }

    public function test_maintaining_an_entry_executes_nothing(): void
    {
        $executed = 0;

        $this->subject->maintain(
            42,
            new Entry(
                new Dn('cn=smith,dc=example,dc=com'),
                new Attribute('cn', 'smith'),
            ),
            static function () use (&$executed): void {
                $executed++;
            },
        );

        self::assertSame(
            0,
            $executed,
        );
    }

    public function test_it_declines_every_substring_predicate(): void
    {
        self::assertNull($this->subject->buildSubstringPredicate(
            'cn',
            ['smi'],
        ));
    }
}
