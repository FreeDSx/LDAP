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

namespace Tests\Integration\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * The entries the server generates rather than reads from storage still honour the request filter.
 */
final class LdapGeneratedEntryFilterTest extends ServerTestCase
{
    private const SUBSCHEMA_DN = 'cn=Subschema';

    private const MONITOR_DN = 'cn=monitor';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--monitor'],
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

    public function test_the_root_dse_is_returned_for_the_standard_probe(): void
    {
        $this->authenticateUser();

        // RFC 4512 section 5.1 has clients read the Root DSE with this filter.
        self::assertCount(
            1,
            $this->searchBase('', Filters::present('objectClass')),
        );
    }

    public function test_the_root_dse_is_withheld_when_the_filter_does_not_match(): void
    {
        $this->authenticateUser();

        self::assertCount(
            0,
            $this->searchBase('', Filters::equal('objectClass', 'banana')),
        );
    }

    public function test_the_root_dse_still_matches_when_only_some_attributes_are_requested(): void
    {
        $this->authenticateUser();

        // Selecting attributes must not change whether the entry matches.
        $entries = $this->searchBase(
            '',
            Filters::present('objectClass'),
            ['namingContexts'],
        );

        self::assertCount(1, $entries);
        self::assertNotNull($entries->first()?->get('namingContexts'));
    }

    public function test_the_subschema_entry_is_returned_when_the_filter_matches(): void
    {
        $this->authenticateUser();

        self::assertCount(
            1,
            $this->searchBase(self::SUBSCHEMA_DN, Filters::equal('objectClass', 'subschema')),
        );
    }

    public function test_the_subschema_entry_is_withheld_when_the_filter_does_not_match(): void
    {
        $this->authenticateUser();

        self::assertCount(
            0,
            $this->searchBase(self::SUBSCHEMA_DN, Filters::equal('objectClass', 'banana')),
        );
    }

    public function test_a_schema_definition_is_found_by_its_leading_oid(): void
    {
        $this->authenticateUser();

        // objectIdentifierFirstComponentMatch, which is how a client looks a definition up by OID.
        self::assertCount(
            1,
            $this->searchBase(self::SUBSCHEMA_DN, Filters::equal('objectClasses', '2.5.6.6')),
        );
    }

    public function test_a_schema_definition_is_not_found_by_an_unrelated_oid(): void
    {
        $this->authenticateUser();

        self::assertCount(
            0,
            $this->searchBase(self::SUBSCHEMA_DN, Filters::equal('objectClasses', '2.5.6.99')),
        );
    }

    public function test_the_monitor_entry_is_returned_when_the_filter_matches(): void
    {
        $this->authenticateAdmin();

        self::assertCount(
            1,
            $this->searchBase(self::MONITOR_DN, Filters::equal('objectClass', 'extensibleObject')),
        );
    }

    public function test_the_monitor_entry_is_withheld_when_the_filter_does_not_match(): void
    {
        $this->authenticateAdmin();

        self::assertCount(
            0,
            $this->searchBase(self::MONITOR_DN, Filters::equal('objectClass', 'banana')),
        );
    }

    public function test_an_unbound_client_may_read_the_root_dse(): void
    {
        // RFC 4513 section 5.2.1.5: discovery has to work before a bind, so this route is never gated.
        self::assertCount(
            1,
            $this->searchBase('', Filters::present('objectClass')),
        );
    }

    public function test_an_unbound_client_may_not_read_the_subschema_entry(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->searchBase(self::SUBSCHEMA_DN, Filters::present('objectClass'));
    }

    public function test_an_unbound_client_may_not_read_the_monitor_entry(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->searchBase(self::MONITOR_DN, Filters::present('objectClass'));
    }

    public function test_an_ordinary_identity_may_read_the_subschema_entry(): void
    {
        $this->authenticateUser();

        self::assertCount(
            1,
            $this->searchBase(self::SUBSCHEMA_DN, Filters::present('objectClass')),
        );
    }

    public function test_an_ordinary_identity_may_not_read_the_monitor_entry(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->searchBase(self::MONITOR_DN, Filters::present('objectClass'));
    }

    public function test_an_administrator_may_read_the_monitor_entry(): void
    {
        $this->authenticateAdmin();

        self::assertCount(
            1,
            $this->searchBase(self::MONITOR_DN, Filters::present('objectClass')),
        );
    }

    public function test_the_monitor_default_can_be_loosened_to_any_authenticated_identity(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--monitor', '--open-monitor']);
        $this->authenticateUser();

        self::assertCount(
            1,
            $this->searchBase(self::MONITOR_DN, Filters::present('objectClass')),
        );
    }

    public function test_the_subschema_default_can_be_tightened_to_the_administrator(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--monitor', '--admin-only-subschema']);
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->searchBase(self::SUBSCHEMA_DN, Filters::present('objectClass'));
    }

    public function test_a_denied_root_dse_attribute_is_stripped_but_the_entry_still_returns(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--monitor', '--hide-rootdse-vendor']);

        $entries = $this->searchBase('', Filters::present('objectClass'), ['+']);
        $entry = $entries->first();

        self::assertNotNull($entry);
        self::assertNull($entry->get('vendorName'));
        self::assertNotNull($entry->get('supportedSaslMechanisms') ?? $entry->get('namingContexts'));
    }

    public function test_the_subschema_withholds_its_definitions_unless_they_are_asked_for(): void
    {
        $this->authenticateUser();

        self::assertSame(
            ['objectClass', 'cn'],
            $this->attributeNamesOf(self::SUBSCHEMA_DN, []),
        );
        self::assertContains(
            'objectClasses',
            $this->attributeNamesOf(self::SUBSCHEMA_DN, ['+']),
        );
    }

    /**
     * The filter runs against the whole entry, so narrowing the selection must not change what matched.
     */
    public function test_a_schema_definition_still_matches_when_it_is_not_selected(): void
    {
        $this->authenticateUser();

        $entries = $this->searchBase(
            self::SUBSCHEMA_DN,
            Filters::equal('objectClasses', '2.5.6.6'),
            ['cn'],
        );

        self::assertCount(1, $entries);
        self::assertSame(
            ['cn'],
            array_keys($entries->first()?->toArray() ?? []),
        );
    }

    public function test_the_monitor_entry_narrows_to_the_requested_attributes(): void
    {
        $this->authenticateAdmin();

        self::assertSame(
            ['connectionsActive'],
            $this->attributeNamesOf(self::MONITOR_DN, ['connectionsActive']),
        );
    }

    /**
     * @param list<string> $attributes
     * @return list<string>
     */
    private function attributeNamesOf(
        string $base,
        array $attributes,
    ): array {
        $entry = $this->searchBase(
            $base,
            Filters::present('objectClass'),
            $attributes,
        )->first();

        self::assertNotNull($entry);

        return array_keys($entry->toArray());
    }

    /**
     * @param list<string> $attributes
     */
    private function searchBase(
        string $base,
        FilterInterface $filter,
        array $attributes = [],
    ): Entries {
        $search = Operations::search($filter)
            ->base($base)
            ->useBaseScope();

        if ($attributes !== []) {
            $search->select(...$attributes);
        }

        return $this->ldapClient()->search($search);
    }
}
