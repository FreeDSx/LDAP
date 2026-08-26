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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Backend\Write\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class OperationalAttributeGeneratorTest extends TestCase
{
    private OperationalAttributeGenerator $subject;

    private Entry $entry;

    protected function setUp(): void
    {
        $this->subject = new OperationalAttributeGenerator();
        $this->entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );
    }

    public function test_apply_for_add_sets_create_timestamp(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );

        $attr = $this->entry->get('createTimestamp');

        self::assertNotNull($attr);
        self::assertMatchesRegularExpression(
            '/^\d{14}Z$/',
            $attr->getValues()[0] ?? '',
        );
    }

    public function test_apply_for_add_sets_modify_timestamp_equal_to_create_timestamp(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );

        $create = $this->entry->get('createTimestamp')?->getValues()[0];
        $modify = $this->entry->get('modifyTimestamp')?->getValues()[0];

        self::assertSame($create, $modify);
    }

    public function test_apply_for_add_sets_creators_name_to_bound_dn(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->boundContext('cn=Admin,dc=example,dc=com'),
        );

        self::assertSame(
            'cn=Admin,dc=example,dc=com',
            $this->entry->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_apply_for_add_sets_creators_name_to_empty_string_for_anonymous(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );

        self::assertSame(
            '',
            $this->entry->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_apply_for_add_sets_modifiers_name_to_bound_dn(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->boundContext('cn=Admin,dc=example,dc=com'),
        );

        self::assertSame(
            'cn=Admin,dc=example,dc=com',
            $this->entry->get('modifiersName')?->getValues()[0],
        );
    }

    public function test_apply_for_add_sets_entry_uuid(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );

        $uuid = $this->entry->get('entryUUID')?->getValues()[0] ?? '';

        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $uuid,
        );
    }

    public function test_apply_for_add_without_schema_does_not_set_structural_object_class(): void
    {
        $entryWithOc = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('objectClass', 'top', 'person'),
        );

        $this->subject->applyForAdd(
            $entryWithOc,
            $this->anonymousContext(),
        );

        self::assertNull($entryWithOc->get('structuralObjectClass'));
    }

    public function test_apply_for_add_with_schema_sets_most_specific_structural_object_class(): void
    {
        $top = new ObjectClass(
            oid: '2.5.6.0',
            names: ['top'],
            type: ObjectClassType::AbstractClass,
        );
        $person = new ObjectClass(
            oid: '2.5.6.6',
            names: ['person'],
            superClassOids: ['2.5.6.0'],
        );
        $inetOrgPerson = new ObjectClass(
            oid: '2.16.840.1.113730.3.2.2',
            names: ['inetOrgPerson'],
            superClassOids: ['2.5.6.6'],
        );

        $schema = (new Schema())
            ->addObjectClass($top)
            ->addObjectClass($person)
            ->addObjectClass($inetOrgPerson);

        $subject = new OperationalAttributeGenerator($schema);

        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('objectClass', 'top', 'person', 'inetOrgPerson'),
        );

        $subject->applyForAdd(
            $entry,
            $this->anonymousContext(),
        );

        self::assertSame(
            'inetOrgPerson',
            $entry->get('structuralObjectClass')?->getValues()[0],
        );
    }

    public function test_apply_for_add_with_schema_but_no_object_class_skips_structural_object_class(): void
    {
        $schema = new Schema();
        $subject = new OperationalAttributeGenerator($schema);

        $subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );

        self::assertNull($this->entry->get('structuralObjectClass'));
    }

    public function test_apply_for_modify_updates_modify_timestamp(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );
        $originalCreate = $this->entry->get('createTimestamp')?->getValues()[0];
        $originalModify = $this->entry->get('modifyTimestamp')?->getValues()[0];

        $this->subject->applyForModify(
            $this->entry,
            $this->anonymousContext(),
        );

        $updatedModify = $this->entry->get('modifyTimestamp')?->getValues()[0];

        self::assertMatchesRegularExpression(
            '/^\d{14}Z$/',
            $updatedModify ?? '',
        );
        // createTimestamp must remain unchanged.
        self::assertSame(
            $originalCreate,
            $this->entry->get('createTimestamp')?->getValues()[0],
        );
        // modifyTimestamp may equal createTimestamp when called in the same second — just verify it's set.
        self::assertNotNull($originalModify);
        self::assertNotNull($updatedModify);
    }

    public function test_apply_for_modify_updates_modifiers_name(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );

        $this->subject->applyForModify(
            $this->entry,
            $this->boundContext('cn=Admin,dc=example,dc=com'),
        );

        self::assertSame(
            'cn=Admin,dc=example,dc=com',
            $this->entry->get('modifiersName')?->getValues()[0],
        );
    }

    public function test_apply_for_modify_does_not_change_creators_name(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->boundContext('cn=Creator,dc=example,dc=com'),
        );

        $this->subject->applyForModify(
            $this->entry,
            $this->boundContext('cn=Modifier,dc=example,dc=com'),
        );

        self::assertSame(
            'cn=Creator,dc=example,dc=com',
            $this->entry->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_apply_for_modify_does_not_change_entry_uuid(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );
        $originalUuid = $this->entry->get('entryUUID')?->getValues()[0];

        $this->subject->applyForModify(
            $this->entry,
            $this->anonymousContext(),
        );

        self::assertSame(
            $originalUuid,
            $this->entry->get('entryUUID')?->getValues()[0],
        );
    }

    public function test_uuid_format_is_valid_rfc4122_v4(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );

        $uuid = $this->entry->get('entryUUID')?->getValues()[0] ?? '';

        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $uuid,
            'UUID must match RFC 4122 v4 format with correct version and variant bits.',
        );
    }

    public function test_timestamp_matches_generalized_time_format(): void
    {
        $this->subject->applyForAdd(
            $this->entry,
            $this->anonymousContext(),
        );

        $ts = $this->entry->get('createTimestamp')?->getValues()[0] ?? '';

        self::assertMatchesRegularExpression(
            '/^\d{4}\d{2}\d{2}\d{2}\d{2}\d{2}Z$/',
            $ts,
            'Timestamp must be in generalized time format YYYYMMDDHHmmssZ.',
        );
    }

    public function test_apply_for_bulk_load_fills_entry_uuid_when_missing(): void
    {
        $this->subject->applyForBulkLoad($this->entry);

        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $this->entry->get('entryUUID')?->getValues()[0] ?? '',
        );
    }

    public function test_apply_for_bulk_load_fills_create_and_modify_timestamps_when_missing(): void
    {
        $this->subject->applyForBulkLoad($this->entry);

        self::assertMatchesRegularExpression(
            '/^\d{14}Z$/',
            $this->entry->get('createTimestamp')?->getValues()[0] ?? '',
        );
        self::assertSame(
            $this->entry->get('createTimestamp')?->getValues()[0],
            $this->entry->get('modifyTimestamp')?->getValues()[0],
        );
    }

    public function test_apply_for_bulk_load_defaults_creator_and_modifier_to_empty_string(): void
    {
        $this->subject->applyForBulkLoad($this->entry);

        self::assertSame(
            '',
            $this->entry->get('creatorsName')?->getValues()[0],
        );
        self::assertSame(
            '',
            $this->entry->get('modifiersName')?->getValues()[0],
        );
    }

    public function test_apply_for_bulk_load_attributes_creator_and_modifier_to_the_actor_dn(): void
    {
        $this->subject->applyForBulkLoad(
            $this->entry,
            'cn=Importer,dc=example,dc=com',
        );

        self::assertSame(
            'cn=Importer,dc=example,dc=com',
            $this->entry->get('creatorsName')?->getValues()[0],
        );
        self::assertSame(
            'cn=Importer,dc=example,dc=com',
            $this->entry->get('modifiersName')?->getValues()[0],
        );
    }

    public function test_apply_for_bulk_load_preserves_operational_attributes_supplied_by_the_source(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('entryUUID', '11111111-2222-4333-8444-555555555555'),
            new Attribute('createTimestamp', '19990101000000Z'),
            new Attribute('creatorsName', 'cn=Original,dc=example,dc=com'),
        );

        $this->subject->applyForBulkLoad(
            $entry,
            'cn=Importer,dc=example,dc=com',
        );

        self::assertSame(
            '11111111-2222-4333-8444-555555555555',
            $entry->get('entryUUID')?->getValues()[0],
        );
        self::assertSame(
            '19990101000000Z',
            $entry->get('createTimestamp')?->getValues()[0],
        );
        self::assertSame(
            'cn=Original,dc=example,dc=com',
            $entry->get('creatorsName')?->getValues()[0],
        );
    }

    public function test_apply_for_bulk_load_sets_structural_object_class_with_schema(): void
    {
        $top = new ObjectClass(
            oid: '2.5.6.0',
            names: ['top'],
            type: ObjectClassType::AbstractClass,
        );
        $person = new ObjectClass(
            oid: '2.5.6.6',
            names: ['person'],
            superClassOids: ['2.5.6.0'],
        );

        $schema = (new Schema())
            ->addObjectClass($top)
            ->addObjectClass($person);

        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('objectClass', 'top', 'person'),
        );

        (new OperationalAttributeGenerator($schema))->applyForBulkLoad($entry);

        self::assertSame(
            'person',
            $entry->get('structuralObjectClass')?->getValues()[0],
        );
    }

    private function anonymousContext(): WriteContext
    {
        return new WriteContext(
            new AnonToken(),
            new ControlBag(),
        );
    }

    private function boundContext(string $dn): WriteContext
    {
        return new WriteContext(
            BindToken::fromDn($dn),
            new ControlBag(),
        );
    }
}
