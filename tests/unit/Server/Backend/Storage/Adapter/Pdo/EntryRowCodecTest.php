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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryRowCodec;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use PHPUnit\Framework\TestCase;

final class EntryRowCodecTest extends TestCase
{
    private const DN = 'cn=Alice,dc=example,dc=com';

    private EntryRowCodec $subject;

    protected function setUp(): void
    {
        $this->subject = new EntryRowCodec(new LinkedAttributes(SchemaResource::Core->load()));
    }

    public function test_attribute_values_round_trip(): void
    {
        $entry = $this->roundTrip(new Entry(
            new Dn(self::DN),
            new Attribute('cn', 'Alice', 'Al'),
            new Attribute('userPassword', 'secret'),
        ));

        self::assertSame(
            ['Alice', 'Al'],
            $entry->get('cn')?->getValues(),
        );
        self::assertSame(
            ['secret'],
            $entry->get('userPassword')?->getValues(),
        );
    }

    public function test_attribute_options_round_trip_as_distinct_attributes(): void
    {
        $entry = $this->roundTrip(new Entry(
            new Dn(self::DN),
            new Attribute('cn', 'Common'),
            new Attribute('cn;lang-en', 'English'),
            new Attribute('userCertificate;binary', 'CERTDATA'),
        ));

        self::assertSame(
            ['Common'],
            $entry->get(new Attribute('cn'), true)?->getValues(),
        );
        self::assertSame(
            ['English'],
            $entry->get(new Attribute('cn;lang-en'), true)?->getValues(),
        );
        self::assertSame(
            ['CERTDATA'],
            $entry->get(new Attribute('userCertificate;binary'), true)?->getValues(),
        );
    }

    public function test_attribute_name_casing_is_preserved(): void
    {
        $entry = $this->roundTrip(new Entry(
            new Dn(self::DN),
            new Attribute('userPassword', 'secret'),
        ));

        self::assertSame(
            ['userPassword'],
            $this->descriptions($entry),
        );
    }

    public function test_the_row_dn_is_kept_verbatim(): void
    {
        $entry = $this->subject->decode(['dn' => 'CN=Alice, DC=Example,DC=com']);

        self::assertSame(
            'CN=Alice, DC=Example,DC=com',
            $entry->getDn()->toString(),
        );
    }

    public function test_a_projection_of_nothing_keeps_only_the_dn(): void
    {
        $entry = $this->subject->decode(
            [
                'dn' => self::DN,
                'attributes' => 'NOT_VALID_BLOB',
            ],
            [],
        );

        self::assertSame(
            self::DN,
            $entry->getDn()->toString(),
        );
        self::assertSame(
            [],
            $entry->getAttributes(),
        );
    }

    public function test_a_projection_keeps_the_allowed_base_names_and_their_option_forms(): void
    {
        $entry = $this->subject->decode(
            $this->rowFor(new Entry(
                new Dn(self::DN),
                new Attribute('cn', 'narrow'),
                new Attribute('cn;lang-en', 'Narrow EN'),
                new Attribute('sn', 'Surname'),
                new Attribute('mail', 'narrow@example.com'),
            )),
            ['cn' => true],
        );

        self::assertSame(
            ['cn', 'cn;lang-en'],
            $this->descriptions($entry),
        );
    }

    public function test_no_projection_keeps_every_attribute_in_stored_order(): void
    {
        $entry = $this->roundTrip(new Entry(
            new Dn(self::DN),
            new Attribute('cn', 'full'),
            new Attribute('sn', 'Surname'),
            new Attribute('mail', 'full@example.com'),
        ));

        self::assertSame(
            ['cn', 'sn', 'mail'],
            $this->descriptions($entry),
        );
    }

    public function test_linked_values_are_added_to_the_entry(): void
    {
        $entry = $this->subject->decode(
            $this->rowFor(new Entry(
                new Dn(self::DN),
                new Attribute('cn', 'group'),
            )),
            null,
            ['member' => ['cn=Bob,dc=example,dc=com']],
        );

        self::assertSame(
            ['cn=Bob,dc=example,dc=com'],
            $entry->get('member')?->getValues(),
        );
    }

    public function test_a_projection_leaves_out_linked_values_it_does_not_name(): void
    {
        $entry = $this->subject->decode(
            $this->rowFor(new Entry(
                new Dn(self::DN),
                new Attribute('cn', 'group'),
            )),
            ['cn' => true],
            ['member' => ['cn=Bob,dc=example,dc=com']],
        );

        self::assertSame(
            ['cn'],
            $this->descriptions($entry),
        );
    }

    public function test_a_projected_child_flag_becomes_has_subordinates(): void
    {
        $row = $this->rowFor(new Entry(new Dn(self::DN)));

        self::assertSame(
            ['TRUE'],
            $this->subject->decode([...$row, 'has_children' => 1])->get('hasSubordinates')?->getValues(),
        );
        self::assertSame(
            ['FALSE'],
            $this->subject->decode([...$row, 'has_children' => 0])->get('hasSubordinates')?->getValues(),
        );
    }

    public function test_a_row_without_the_child_flag_carries_no_has_subordinates(): void
    {
        $entry = $this->roundTrip(new Entry(new Dn(self::DN)));

        self::assertNull($entry->get('hasSubordinates'));
    }

    public function test_decoding_a_corrupted_blob_is_refused(): void
    {
        $this->expectException(StorageIoException::class);

        $this->subject->decode([
            'dn' => self::DN,
            'attributes' => 'NOT_VALID_BLOB',
        ]);
    }

    private function roundTrip(Entry $entry): Entry
    {
        return $this->subject->decode($this->rowFor($entry));
    }

    /**
     * @return array{dn: string, attributes: string}
     */
    private function rowFor(Entry $entry): array
    {
        return [
            'dn' => $entry->getDn()->toString(),
            'attributes' => $this->subject->encode($entry),
        ];
    }

    /**
     * @return list<string>
     */
    private function descriptions(Entry $entry): array
    {
        return array_values(array_map(
            static fn(Attribute $attribute): string => $attribute->getDescription(),
            $entry->getAttributes(),
        ));
    }
}
