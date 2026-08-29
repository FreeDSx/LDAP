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

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\GeneratedEntry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class GeneratedEntryTest extends TestCase
{
    #[DataProvider('generatedDnProvider')]
    public function test_it_resolves_the_entry_generated_at_a_dn(
        string $dn,
        GeneratedEntry $expected,
    ): void {
        self::assertSame(
            $expected,
            GeneratedEntry::at(new Dn($dn)),
        );
    }

    /**
     * @return iterable<string, array{string, GeneratedEntry}>
     */
    public static function generatedDnProvider(): iterable
    {
        yield 'the zero length dn' => [
            '',
            GeneratedEntry::RootDse,
        ];
        yield 'the subschema dn' => [
            'cn=Subschema',
            GeneratedEntry::Subschema,
        ];
        // RFC 4514 permits whitespace around the separator and the type is case insensitive.
        yield 'the subschema dn spelled with padding' => [
            'cn = Subschema',
            GeneratedEntry::Subschema,
        ];
        yield 'the subschema dn spelled in another case' => [
            'CN=SUBSCHEMA',
            GeneratedEntry::Subschema,
        ];
        yield 'the monitor dn' => [
            'cn=monitor',
            GeneratedEntry::Monitor,
        ];
        yield 'the monitor dn spelled in another case' => [
            'CN=Monitor',
            GeneratedEntry::Monitor,
        ];
    }

    #[DataProvider('ordinaryDnProvider')]
    public function test_an_ordinary_dn_generates_nothing(string $dn): void
    {
        self::assertNull(GeneratedEntry::at(new Dn($dn)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ordinaryDnProvider(): iterable
    {
        yield 'a naming context' => ['dc=foo,dc=bar'];
        yield 'an entry beneath one' => ['cn=alice,dc=foo,dc=bar'];
        // Only the reserved name itself is taken, not the same RDN somewhere else in the tree.
        yield 'the subschema rdn beneath a naming context' => ['cn=Subschema,dc=foo,dc=bar'];
        yield 'the monitor rdn beneath a naming context' => ['cn=monitor,dc=foo,dc=bar'];
    }

    public function test_a_null_dn_generates_nothing(): void
    {
        self::assertNull(GeneratedEntry::at(null));
    }

    #[DataProvider('everyEntryProvider')]
    public function test_its_dn_resolves_back_to_it(GeneratedEntry $entry): void
    {
        self::assertSame(
            $entry,
            GeneratedEntry::at($entry->dn()),
        );
    }

    #[DataProvider('everyEntryProvider')]
    public function test_it_has_a_label_for_a_refusal_message(GeneratedEntry $entry): void
    {
        self::assertNotSame(
            '',
            $entry->label(),
        );
    }

    /**
     * @return iterable<string, array{GeneratedEntry}>
     */
    public static function everyEntryProvider(): iterable
    {
        foreach (GeneratedEntry::cases() as $entry) {
            yield $entry->name => [$entry];
        }
    }
}
