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

namespace Tests\Integration\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * A schema parsed from LDIF drives validation exactly as one built in PHP does.
 */
final class LdapLoadedSchemaTest extends ServerTestCase
{
    private const SCHEMA_LDIF = __DIR__ . '/../../resources/schema/custom-subschema.ldif';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--schema-ldif=' . self::SCHEMA_LDIF],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function test_an_entry_using_a_loaded_object_class_is_accepted(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-ok,dc=foo,dc=bar',
            [
                'cn' => 'loaded-ok',
                'objectClass' => 'projectRecord',
                'projectCode' => 'apollo',
                'projectNotes' => 'from a loaded schema',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'loaded-ok'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'apollo',
            $entries->first()?->get('projectCode')?->firstValue(),
        );
    }

    public function test_a_loaded_object_class_enforces_its_required_attributes(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'projectCode' is MUST on the loaded 'projectRecord' class.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-missing-must,dc=foo,dc=bar',
            [
                'cn' => 'loaded-missing-must',
                'objectClass' => 'projectRecord',
            ],
        ));
    }

    public function test_a_loaded_object_class_rejects_an_attribute_it_does_not_permit(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        // 'sn' is neither MUST nor MAY on the loaded 'projectRecord' class.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-extra-attr,dc=foo,dc=bar',
            [
                'cn' => 'loaded-extra-attr',
                'objectClass' => 'projectRecord',
                'projectCode' => 'gemini',
                'sn' => 'Nope',
            ],
        ));
    }

    public function test_a_loaded_attribute_is_searchable_by_its_matching_rules(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-search,dc=foo,dc=bar',
            [
                'cn' => 'loaded-search',
                'objectClass' => 'projectRecord',
                'projectCode' => 'Voyager',
            ],
        ));

        // The loaded definition declares caseIgnoreMatch and caseIgnoreSubstringsMatch.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::contains('projectCode', 'oyag'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'loaded-search',
            $entries->first()?->get('cn')?->firstValue(),
        );
    }

    public function test_the_standard_schema_still_applies_alongside_loaded_definitions(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=loaded-standard,dc=foo,dc=bar',
            [
                'cn' => 'loaded-standard',
                'sn' => 'Standard',
                'objectClass' => 'person',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'loaded-standard'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
    }
}
