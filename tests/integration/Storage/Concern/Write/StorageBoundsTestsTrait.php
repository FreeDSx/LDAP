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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write;

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * What the storage holds at its edges: values that are binary or large, wide attributes, and long attribute types.
 */
trait StorageBoundsTestsTrait
{
    public function testAddStoresAValueThatIsNotUtf8(): void
    {
        $photo = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x02\x03\xFE";

        $this->asAdmin(fn(LdapClient $admin) => $admin->create(new Entry(
            'cn=binary,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'binary'),
            new Attribute('sn', 'Binary'),
            new Attribute('jpegPhoto', $photo),
        )));

        self::assertSame(
            $photo,
            $this->ldapClient()->read('cn=binary,dc=foo,dc=bar')?->get('jpegPhoto')?->firstValue(),
        );
        self::assertCount(
            1,
            $this->ldapClient()->search(
                Operations::search(Filters::present('jpegPhoto'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=binary,dc=foo,dc=bar'));
    }

    public function testAddStoresAValueLargerThanSixtyFourKilobytes(): void
    {
        $value = str_repeat('a', 70000);

        $this->asAdmin(fn(LdapClient $admin) => $admin->create(new Entry(
            'cn=oversized,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'oversized'),
            new Attribute('sn', 'Oversized'),
            new Attribute('description', $value),
        )));

        self::assertSame(
            $value,
            $this->ldapClient()->read('cn=oversized,dc=foo,dc=bar')?->get('description')?->firstValue(),
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=oversized,dc=foo,dc=bar'));
    }

    public function testAddStoresAnAttributeWiderThanOneIndexStatement(): void
    {
        $values = [];
        foreach (range(1, 300) as $i) {
            $values[] = "wide value {$i}";
        }

        $this->asAdmin(fn(LdapClient $admin) => $admin->create(new Entry(
            'cn=wideattr,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'wideattr'),
            new Attribute('sn', 'Wide'),
            new Attribute('description', ...$values),
        )));

        try {
            self::assertCount(
                300,
                $this->ldapClient()->read('cn=wideattr,dc=foo,dc=bar')?->get('description')?->getValues() ?? [],
            );
            self::assertCount(
                1,
                $this->ldapClient()->search(
                    Operations::search(Filters::equal('description', 'wide value 300'), 'cn')
                        ->base('dc=foo,dc=bar')
                        ->useSubtreeScope(),
                )->toArray(),
            );
        } finally {
            $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=wideattr,dc=foo,dc=bar'));
        }
    }

    public function testModifyOfAWideAttributeKeepsEveryOtherValueSearchable(): void
    {
        $values = [];
        foreach (range(1, 300) as $i) {
            $values[] = "growing value {$i}";
        }

        $this->asAdmin(fn(LdapClient $admin) => $admin->create(new Entry(
            'cn=growingattr,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'growingattr'),
            new Attribute('sn', 'Growing'),
            new Attribute('description', ...$values),
        )));

        try {
            $this->asAdmin(fn(LdapClient $admin) => $admin->send(Operations::modify(
                'cn=growingattr,dc=foo,dc=bar',
                Change::add(new Attribute('description', 'growing value 301')),
            )));

            foreach (['growing value 1', 'growing value 301'] as $value) {
                self::assertCount(
                    1,
                    $this->ldapClient()->search(
                        Operations::search(Filters::equal('description', $value), 'cn')
                            ->base('dc=foo,dc=bar')
                            ->useSubtreeScope(),
                    )->toArray(),
                    $value,
                );
            }
        } finally {
            $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=growingattr,dc=foo,dc=bar'));
        }
    }

    public function testAnEqualityAssertionAtTheIndexLimitDoesNotMatchALongerValue(): void
    {
        // The second key is cut just after a space, which MySQL compares as equal to the prefix without it.
        $entries = [
            'cutatlimit' => str_repeat('l', 255) . 'tail',
            'cutafterspace' => str_repeat('l', 254) . ' tail',
        ];

        $this->asAdmin(function (LdapClient $admin) use ($entries): void {
            foreach ($entries as $cn => $description) {
                $admin->create(new Entry(
                    "cn={$cn},dc=foo,dc=bar",
                    new Attribute('objectClass', 'top', 'inetOrgPerson'),
                    new Attribute('cn', $cn),
                    new Attribute('sn', 'Cut'),
                    new Attribute('description', $description),
                ));
            }
        });

        try {
            foreach ([255, 254] as $length) {
                self::assertSame(
                    [],
                    $this->ldapClient()->search(
                        Operations::search(Filters::equal('description', str_repeat('l', $length)), 'cn')
                            ->base('dc=foo,dc=bar')
                            ->useSubtreeScope(),
                    )->toArray(),
                    "assertion of {$length} characters",
                );
            }
        } finally {
            $this->asAdmin(function (LdapClient $admin) use ($entries): void {
                foreach (array_keys($entries) as $cn) {
                    $admin->delete("cn={$cn},dc=foo,dc=bar");
                }
            });
        }
    }

    public function testAnAttributeTypeWithinTheStorageBoundIsStored(): void
    {
        // The type is undefined, which only a lenient policy waives.
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--validation-mode=lenient',
            ],
        );
        $type = 'a' . str_repeat('b', Attribute::MAX_TYPE_LENGTH - 1);

        $this->asAdmin(fn(LdapClient $admin) => $admin->send(Operations::add(new Entry(
            'cn=longattr,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'longattr'),
            new Attribute('sn', 'Long'),
            new Attribute($type, 'value'),
        ))));

        self::assertSame(
            'value',
            $this->ldapClient()->read('cn=longattr,dc=foo,dc=bar')?->get($type)?->firstValue(),
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=longattr,dc=foo,dc=bar'));
    }

    public function testAnOverLongAttributeTypeIsRefusedAndTheSessionSurvives(): void
    {
        $this->authenticateAdmin();
        $type = 'a' . str_repeat('b', Attribute::MAX_TYPE_LENGTH);

        try {
            $this->ldapClient()->send(
                Operations::add(new Entry(
                    'cn=toolongattr,dc=foo,dc=bar',
                    new Attribute('objectClass', 'top', 'inetOrgPerson'),
                    new Attribute('cn', 'toolongattr'),
                    new Attribute('sn', 'Too Long'),
                    new Attribute($type, 'value'),
                )),
                Controls::relaxRules(),
            );
            self::fail('An attribute type beyond the storage bound should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
        }

        // The refusal answers the operation rather than dropping the connection, so the session still serves.
        self::assertNotNull($this->ldapClient()->read('cn=admin,dc=foo,dc=bar'));
    }

    public function testAnAttributeDescriptionNamingNoTypeIsRefusedWithValidationOff(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--validation-mode=off',
            ],
        );
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->ldapClient()->send(Operations::add(new Entry(
            'cn=notype,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'notype'),
            new Attribute('sn', 'No Type'),
            new Attribute(';sn', 'value'),
        )));
    }

    public function testANonAsciiAttributeTypeIsRefusedAsUndefinedWithValidationOff(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--validation-mode=off',
            ],
        );
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->ldapClient()->send(Operations::add(new Entry(
            'cn=nonascii,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'nonascii'),
            new Attribute('sn', 'Non Ascii'),
            new Attribute('café', 'value'),
        )));
    }

    public function testAModifyAddingADescriptionNamingNoTypeIsRefusedWithValidationOff(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--validation-mode=off',
            ],
        );
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->ldapClient()->send(Operations::modify(
            'cn=user,dc=foo,dc=bar',
            Change::add(
                ';cn',
                'value',
            ),
        ));
    }
}
