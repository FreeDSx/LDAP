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
        $this->authenticateUser();

        self::assertCount(
            1,
            $this->searchBase(self::MONITOR_DN, Filters::equal('objectClass', 'extensibleObject')),
        );
    }

    public function test_the_monitor_entry_is_withheld_when_the_filter_does_not_match(): void
    {
        $this->authenticateUser();

        self::assertCount(
            0,
            $this->searchBase(self::MONITOR_DN, Filters::equal('objectClass', 'banana')),
        );
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
