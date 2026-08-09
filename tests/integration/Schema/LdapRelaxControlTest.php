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

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end Relax Rules control behaviour; the shared server runs Strict validation and grants relax to
 * authenticated identities.
 */
final class LdapRelaxControlTest extends ServerTestCase
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
            ['--validation-mode=strict', '--allow-relax'],
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

    public function test_relax_control_allows_a_schema_violating_add(): void
    {
        $this->authenticateAdmin();

        // 'mail' is not permitted by the 'person' object class; rejected under Strict without the control.
        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-add,dc=foo,dc=bar',
                [
                    'cn' => 'relax-add',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'mail' => 'relax-add@foo.bar',
                ],
            ),
            Controls::relaxRules(),
        );

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'relax-add'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'relax-add@foo.bar',
            $entries->first()?->get('mail')?->firstValue(),
        );
    }

    public function test_same_add_is_rejected_under_strict_without_the_control(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=relax-rejected,dc=foo,dc=bar',
            [
                'cn' => 'relax-rejected',
                'sn' => 'Drift',
                'objectClass' => 'person',
                'mail' => 'relax-rejected@foo.bar',
            ],
        ));
    }

    public function test_relax_control_does_not_bypass_invalid_syntax_behind_a_relaxed_violation(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        // entryUUID is NO-USER-MODIFICATION, which relax waives, but its value is still malformed.
        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-bad-uuid,dc=foo,dc=bar',
                [
                    'cn' => 'relax-bad-uuid',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'entryUUID' => 'not-a-uuid',
                ],
            ),
            Controls::relaxRules(),
        );
    }

    public function test_relax_control_does_not_bypass_invalid_attribute_syntax(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(
            Entry::fromArray(
                'cn=relax-bad-syntax,dc=foo,dc=bar',
                [
                    'cn' => 'relax-bad-syntax',
                    'sn' => 'Drift',
                    'objectClass' => 'person',
                    'seeAlso' => 'not a dn',
                ],
            ),
            Controls::relaxRules(),
        );
    }
}
