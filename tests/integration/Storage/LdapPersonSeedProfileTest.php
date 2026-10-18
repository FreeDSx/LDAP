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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * The load test's default seed profile, which the schema must keep accepting with validation on.
 */
final class LdapPersonSeedProfileTest extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();

        $this->createServerProcess(
            'tcp',
            [
                '--seed-profile=person',
                '--seed-entries=21',
                '--seed-attributes=1',
                '--seed-groups=1',
                '--seed-group-size=5',
            ],
        );
        $this->authenticateAdmin();
    }

    public function testEveryPersonAndGroupIsSeeded(): void
    {
        self::assertCount(
            21,
            $this->ldapClient()->search(
                Operations::list(
                    Filters::startsWith('cn', 'seed-'),
                    'ou=people,dc=foo,dc=bar',
                    '1.1',
                ),
            )->toArray(),
        );
        self::assertCount(
            12,
            $this->ldapClient()->search(
                Operations::list(
                    Filters::equal('objectClass', 'groupOfNames'),
                    'ou=groups,dc=foo,dc=bar',
                    '1.1',
                ),
            )->toArray(),
        );
        self::assertNotNull($this->ldapClient()->read('cn=load-group-0,ou=people,dc=foo,dc=bar'));
    }

    public function testAPersonIsRelatedToItsManagerTeamAndDepartment(): void
    {
        $person = $this->ldapClient()->read(
            'cn=seed-21,ou=people,dc=foo,dc=bar',
            ['seeAlso', 'memberOf', 'mail'],
        );

        self::assertNotNull($person);
        self::assertSame(
            ['cn=seed-2,ou=people,dc=foo,dc=bar'],
            $person->get('seeAlso')?->getValues(),
        );
        self::assertEqualsCanonicalizing(
            [
                'cn=team-2,ou=groups,dc=foo,dc=bar',
                'cn=dept-1,ou=groups,dc=foo,dc=bar',
            ],
            $person->get('memberOf')?->getValues(),
        );
        self::assertSame(
            'seed-21@foo.bar',
            $person->get('mail')?->firstValue(),
        );
    }
}
