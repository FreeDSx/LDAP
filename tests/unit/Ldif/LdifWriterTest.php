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

namespace Tests\Unit\FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Ldif\LdifChangeRecord;
use FreeDSx\Ldap\Ldif\LdifChanges;
use FreeDSx\Ldap\Ldif\LdifOutputOptions;
use FreeDSx\Ldap\Ldif\LdifWriter;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LdifWriterTest extends TestCase
{
    public function test_it_writes_an_add_request_with_a_version_header(): void
    {
        $ldif = (new LdifWriter())->write([
            Operations::add(Entry::create(
                'cn=foo,dc=x',
                [
                    'cn' => 'foo',
                    'sn' => 'Bar',
                ],
            )),
        ]);

        self::assertStringStartsWith(
            "version: 1\n\ndn: cn=foo,dc=x\n",
            $ldif,
        );
        self::assertStringContainsString(
            "\ncn: foo\n",
            $ldif,
        );
        self::assertStringContainsString(
            "\nsn: Bar\n",
            $ldif,
        );
    }

    public function test_it_omits_the_version_header_when_disabled(): void
    {
        $ldif = $this->writer()->write([
            Operations::add(Entry::create('cn=foo,dc=x', ['cn' => 'foo'])),
        ]);

        self::assertStringStartsWith(
            'dn: cn=foo,dc=x',
            $ldif,
        );
    }

    public function test_an_add_request_emits_as_a_content_record_by_default(): void
    {
        $ldif = $this->writer()->write([
            Operations::add(Entry::create('cn=foo,dc=x', ['cn' => 'foo'])),
        ]);

        self::assertStringNotContainsString(
            'changetype:',
            $ldif,
        );
    }

    public function test_an_add_request_emits_changetype_add_when_the_option_is_enabled(): void
    {
        $options = (new LdifOutputOptions())
            ->setIncludeVersion(false)
            ->setEmitChangetypeForAdds(true);

        $ldif = (new LdifWriter($options))->write([
            Operations::add(Entry::create('cn=foo,dc=x', ['cn' => 'foo'])),
        ]);

        self::assertStringStartsWith(
            "dn: cn=foo,dc=x\nchangetype: add\n",
            $ldif,
        );
    }

    #[DataProvider('unsafeValues')]
    public function test_it_base64_encodes_values_that_are_not_safe_strings(string $value): void
    {
        $ldif = $this->writer()->write([
            Operations::add(Entry::create('cn=foo,dc=x', ['cn' => $value])),
        ]);

        self::assertStringContainsString(
            'cn:: ' . base64_encode($value),
            $ldif,
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unsafeValues(): array
    {
        return [
            'leading space' => [' leading'],
            'trailing space' => ['trailing '],
            'leading colon' => [':colon'],
            'leading less-than' => ['<value'],
            'non-ascii' => ['Bär'],
            'embedded newline' => ["line1\nline2"],
        ];
    }

    public function test_it_writes_a_safe_value_in_plain_form(): void
    {
        $ldif = $this->writer()->write([
            Operations::add(Entry::create('cn=foo,dc=x', ['cn' => 'plainValue'])),
        ]);

        self::assertStringContainsString(
            "cn: plainValue\n",
            $ldif,
        );
    }

    public function test_it_folds_lines_longer_than_the_max_length(): void
    {
        $options = (new LdifOutputOptions())
            ->setIncludeVersion(false)
            ->setMaxLineLength(20);

        $ldif = (new LdifWriter($options))->write([
            Operations::add(Entry::create(
                'cn=foo,dc=x',
                ['description' => str_repeat('a', 60)],
            )),
        ]);

        self::assertStringContainsString(
            "\n ",
            $ldif,
        );
        foreach (explode("\n", $ldif) as $line) {
            self::assertLessThanOrEqual(
                20,
                strlen($line),
            );
        }
    }

    public function test_it_writes_a_delete_request(): void
    {
        $ldif = $this->writer()->write([
            Operations::delete('cn=foo,dc=x'),
        ]);

        self::assertSame(
            "dn: cn=foo,dc=x\nchangetype: delete\n",
            $ldif,
        );
    }

    public function test_it_writes_a_modify_request_with_a_single_replace_modspec(): void
    {
        $ldif = $this->writer()->write([
            Operations::modify(
                'cn=alice,dc=x',
                Change::replace('sn', 'Anderson'),
            ),
        ]);

        self::assertSame(
            "dn: cn=alice,dc=x\nchangetype: modify\nreplace: sn\nsn: Anderson\n-\n",
            $ldif,
        );
    }

    public function test_it_writes_a_modify_request_with_multiple_modspecs_in_order(): void
    {
        $ldif = $this->writer()->write([
            Operations::modify(
                'cn=alice,dc=x',
                Change::add('telephoneNumber', '555-0100'),
                Change::delete('description'),
                Change::replace('sn', 'Anderson'),
            ),
        ]);

        self::assertSame(
            "dn: cn=alice,dc=x\n"
            . "changetype: modify\n"
            . "add: telephoneNumber\n"
            . "telephoneNumber: 555-0100\n"
            . "-\n"
            . "delete: description\n"
            . "-\n"
            . "replace: sn\n"
            . "sn: Anderson\n"
            . "-\n",
            $ldif,
        );
    }

    public function test_a_modspec_with_no_values_emits_only_the_op_and_terminator(): void
    {
        $ldif = $this->writer()->write([
            Operations::modify(
                'cn=alice,dc=x',
                Change::delete('description'),
            ),
        ]);

        self::assertStringContainsString(
            "delete: description\n-\n",
            $ldif,
        );
    }

    public function test_it_writes_a_modrdn_request_with_newsuperior(): void
    {
        $ldif = $this->writer()->write([
            new ModifyDnRequest(
                'cn=alice,ou=old,dc=x',
                'cn=alicia',
                false,
                'ou=new,dc=x',
            ),
        ]);

        self::assertSame(
            "dn: cn=alice,ou=old,dc=x\n"
            . "changetype: modrdn\n"
            . "newrdn: cn=alicia\n"
            . "deleteoldrdn: 0\n"
            . "newsuperior: ou=new,dc=x\n",
            $ldif,
        );
    }

    public function test_it_writes_a_modrdn_request_without_newsuperior(): void
    {
        $ldif = $this->writer()->write([
            new ModifyDnRequest(
                'cn=alice,dc=x',
                'cn=alicia',
                true,
            ),
        ]);

        self::assertSame(
            "dn: cn=alice,dc=x\n"
            . "changetype: modrdn\n"
            . "newrdn: cn=alicia\n"
            . "deleteoldrdn: 1\n",
            $ldif,
        );
    }

    public function test_a_modrdn_request_base64_encodes_a_non_ascii_newrdn(): void
    {
        $ldif = $this->writer()->write([
            new ModifyDnRequest(
                'cn=foo,dc=x',
                'cn=Bär',
                true,
            ),
        ]);

        self::assertStringContainsString(
            'newrdn:: ' . base64_encode('cn=Bär') . "\n",
            $ldif,
        );
    }

    public function test_it_preserves_input_order_across_mixed_request_types(): void
    {
        $ldif = $this->writer()->write([
            Operations::add(Entry::create('cn=a,dc=x', ['cn' => 'a'])),
            Operations::delete('cn=b,dc=x'),
            Operations::modify(
                'cn=c,dc=x',
                Change::replace('sn', 'C'),
            ),
        ]);

        $aPos = strpos($ldif, 'dn: cn=a,dc=x');
        $bPos = strpos($ldif, 'dn: cn=b,dc=x');
        $cPos = strpos($ldif, 'dn: cn=c,dc=x');

        self::assertNotFalse($aPos);
        self::assertLessThan(
            $bPos,
            $aPos,
        );
        self::assertLessThan(
            $cPos,
            $bPos,
        );
    }

    public function test_it_rejects_an_unsupported_request_type(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported request type for LDIF output');

        $this->writer()->write([
            Operations::bindAnonymously(),
        ]);
    }

    public function test_it_round_trips_through_the_parser_for_all_changetypes(): void
    {
        $options = (new LdifOutputOptions())
            ->setEmitChangetypeForAdds(true);

        $changes = new LdifChanges(
            new LdifChangeRecord(Operations::add(Entry::create('cn=a,dc=x', [
                'objectClass' => ['top', 'person'],
                'cn' => 'a',
                'sn' => ['Bär', ' spaced '],
            ]))),
            new LdifChangeRecord(Operations::delete('cn=b,dc=x')),
            new LdifChangeRecord(Operations::modify(
                'cn=c,dc=x',
                Change::add('telephoneNumber', '555-0100'),
                Change::delete('description'),
                Change::replace('sn', 'C'),
            )),
            new LdifChangeRecord(new ModifyDnRequest(
                'cn=d,ou=old,dc=x',
                'cn=dd',
                true,
                'ou=new,dc=x',
            )),
        );

        $ldif = (new LdifWriter($options))->write($changes->requests());
        $parsed = LdifChanges::fromString($ldif);

        self::assertSame(
            $this->normalize($changes->requests()),
            $this->normalize($parsed->requests()),
        );
    }

    private function writer(): LdifWriter
    {
        return new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false));
    }

    /**
     * @param iterable<RequestInterface> $requests
     * @return list<array<string, mixed>>
     */
    private function normalize(iterable $requests): array
    {
        $out = [];

        foreach ($requests as $request) {
            $out[] = match (true) {
                $request instanceof AddRequest => [
                    'type' => 'add',
                    'dn' => $request->getEntry()->getDn()->toString(),
                    'attrs' => $this->attributesOf($request->getEntry()),
                ],
                $request instanceof DeleteRequest => [
                    'type' => 'delete',
                    'dn' => $request->getDn()->toString(),
                ],
                $request instanceof ModifyRequest => [
                    'type' => 'modify',
                    'dn' => $request->getDn()->toString(),
                    'changes' => array_map(
                        fn(Change $c): array => [
                            'type' => $c->getType(),
                            'attr' => $c->getAttribute()->getDescription(),
                            'values' => $c->getAttribute()->getValues(),
                        ],
                        $request->getChanges(),
                    ),
                ],
                $request instanceof ModifyDnRequest => [
                    'type' => 'modrdn',
                    'dn' => $request->getDn()->toString(),
                    'newRdn' => $request->getNewRdn()->toString(),
                    'deleteOldRdn' => $request->getDeleteOldRdn(),
                    'newSuperior' => $request->getNewParentDn()?->toString(),
                ],
                default => ['type' => 'unknown'],
            };
        }

        return $out;
    }

    /**
     * @return array<string, string[]>
     */
    private function attributesOf(Entry $entry): array
    {
        $attrs = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attrs[$attribute->getDescription()] = $attribute->getValues();
        }

        return $attrs;
    }
}
