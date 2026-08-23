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

namespace Tests\Integration\FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

final class LdapApplyChangesServerTest extends ServerTestCase
{
    private const SEED_LDIF = __DIR__ . '/../../resources/seed/seed-test.ldif';

    private const CHANGES_LDIF = __DIR__ . '/../../resources/changes/apply-test.ldif';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-server',
            'tcp',
            [
                '--seed=' . self::SEED_LDIF,
                '--changes=' . self::CHANGES_LDIF,
            ],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();

        $this->authenticateUser();
    }

    public function test_a_modify_change_replaces_the_attribute_value(): void
    {
        $alice = $this->ldapClient()->read('cn=alice,dc=foo,dc=bar');

        $this->assertNotNull($alice);
        $this->assertSame(
            'Renamed',
            $alice->get('sn')?->firstValue(),
        );
    }

    public function test_a_delete_change_removes_the_entry(): void
    {
        $this->assertNull($this->ldapClient()->read('cn=bob,dc=foo,dc=bar'));
    }

    public function test_a_modrdn_change_renames_the_entry(): void
    {
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('objectClass', 'inetOrgPerson'))
                ->base('dc=foo,dc=bar'),
        );

        $dns = [];
        foreach ($entries as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        $this->assertContains(
            'cn=carolyn,dc=foo,dc=bar',
            $dns,
        );
        $this->assertNotContains(
            'cn=carol,dc=foo,dc=bar',
            $dns,
        );
    }

    public function test_the_renamed_entry_carries_the_added_attributes(): void
    {
        $carolyn = $this->ldapClient()->read('cn=carolyn,dc=foo,dc=bar');

        $this->assertNotNull($carolyn);
        $this->assertSame(
            'Coder',
            $carolyn->get('sn')?->firstValue(),
        );
    }

    /**
     * The changelog adds ou=team with a child, then deletes it carrying "control: 1.2.840.113556.1.4.805 true".
     *
     * Replay runs at test startup, so this asserts the state it left.
     */
    public function test_a_delete_change_carrying_the_subtree_control_removes_the_whole_subtree(): void
    {
        $this->assertNull($this->ldapClient()->read('cn=erin,ou=team,dc=foo,dc=bar'));
        $this->assertNull($this->ldapClient()->read('ou=team,dc=foo,dc=bar'));
    }

    public function test_an_added_entry_groups_descriptions_that_differ_only_in_case(): void
    {
        $dave = $this->ldapClient()->read('cn=dave,dc=foo,dc=bar');

        $this->assertNotNull($dave);
        $this->assertSame(
            ['first', 'second'],
            $dave->get('description')?->getValues(),
        );
    }
}
