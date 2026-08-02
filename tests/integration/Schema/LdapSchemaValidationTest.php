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
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end schema validation behaviour; the shared server runs in Lenient mode.
 */
final class LdapSchemaValidationTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--validation-mode=lenient'],
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

    public function test_lenient_mode_allows_add_with_disallowed_attribute(): void
    {
        $this->authenticateAdmin();

        // 'mail' is not permitted by the 'person' object class; rejected under Strict.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=drift-add,dc=foo,dc=bar',
            [
                'cn' => 'drift-add',
                'sn' => 'Drift',
                'objectClass' => 'person',
                'mail' => 'drift-add@foo.bar',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'drift-add'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'drift-add@foo.bar',
            $entries->first()?->get('mail')?->firstValue(),
        );
    }

    public function test_lenient_mode_allows_modify_into_violating_state(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=drift-modify,dc=foo,dc=bar',
            [
                'cn' => 'drift-modify',
                'sn' => 'Drift',
                'objectClass' => 'person',
            ],
        ));

        // Adding 'mail' makes the merged entry violate the 'person' object class; rejected under Strict.
        $entry = Entry::fromArray('cn=drift-modify,dc=foo,dc=bar');
        $entry->set('mail', 'drift-modify@foo.bar');
        $this->ldapClient()->update($entry);

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'drift-modify'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            'drift-modify@foo.bar',
            $entries->first()?->get('mail')?->firstValue(),
        );
    }
}
