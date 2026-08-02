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

final class LdapSeedServerTest extends ServerTestCase
{
    private const SEED_LDIF = __DIR__ . '/../../resources/seed/seed-test.ldif';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-server',
            'tcp',
            ['--seed=' . self::SEED_LDIF],
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

    public function test_it_serves_a_seeded_entry_with_its_attributes(): void
    {
        $alice = $this->ldapClient()->read('cn=alice,dc=foo,dc=bar');

        $this->assertNotNull($alice);
        $this->assertSame(
            'Anderson',
            $alice->get('sn')?->firstValue(),
        );
    }

    public function test_it_unfolds_a_folded_value_through_to_the_served_entry(): void
    {
        $alice = $this->ldapClient()->read('cn=alice,dc=foo,dc=bar');

        $this->assertNotNull($alice);
        $this->assertSame(
            'A folded description value that is intentionally longer than seventy-six characters so the parser must unfold it.',
            $alice->get('description')?->firstValue(),
        );
    }

    public function test_it_serves_all_seeded_entries_in_a_subtree_search(): void
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
            'cn=alice,dc=foo,dc=bar',
            $dns,
        );
        $this->assertContains(
            'cn=bob,dc=foo,dc=bar',
            $dns,
        );
        $this->assertContains(
            'cn=user,dc=foo,dc=bar',
            $dns,
        );
    }
}
