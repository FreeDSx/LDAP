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
        $this->authenticateAdmin();
        $photo = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x02\x03\xFE";

        $this->ldapClient()->create(new Entry(
            'cn=binary,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'binary'),
            new Attribute('sn', 'Binary'),
            new Attribute('jpegPhoto', $photo),
        ));

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

        $this->ldapClient()->delete('cn=binary,dc=foo,dc=bar');
    }

    public function testAddStoresAValueLargerThanSixtyFourKilobytes(): void
    {
        $this->authenticateAdmin();
        $value = str_repeat('a', 70000);

        $this->ldapClient()->create(new Entry(
            'cn=oversized,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'oversized'),
            new Attribute('sn', 'Oversized'),
            new Attribute('description', $value),
        ));

        self::assertSame(
            $value,
            $this->ldapClient()->read('cn=oversized,dc=foo,dc=bar')?->get('description')?->firstValue(),
        );

        $this->ldapClient()->delete('cn=oversized,dc=foo,dc=bar');
    }

    public function testAddStoresAnAttributeWiderThanOneIndexStatement(): void
    {
        $this->authenticateAdmin();
        $values = [];
        foreach (range(1, 300) as $i) {
            $values[] = "wide value {$i}";
        }

        $this->ldapClient()->create(new Entry(
            'cn=wideattr,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'wideattr'),
            new Attribute('sn', 'Wide'),
            new Attribute('description', ...$values),
        ));

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
            $this->ldapClient()->delete('cn=wideattr,dc=foo,dc=bar');
        }
    }

    public function testModifyOfAWideAttributeKeepsEveryOtherValueSearchable(): void
    {
        $this->authenticateAdmin();
        $values = [];
        foreach (range(1, 300) as $i) {
            $values[] = "growing value {$i}";
        }

        $this->ldapClient()->create(new Entry(
            'cn=growingattr,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'growingattr'),
            new Attribute('sn', 'Growing'),
            new Attribute('description', ...$values),
        ));

        try {
            $this->ldapClient()->send(Operations::modify(
                'cn=growingattr,dc=foo,dc=bar',
                Change::add(new Attribute('description', 'growing value 301')),
            ));

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
            $this->ldapClient()->delete('cn=growingattr,dc=foo,dc=bar');
        }
    }

    public function testAnEqualityAssertionAtTheIndexLimitDoesNotMatchALongerValue(): void
    {
        $this->authenticateAdmin();
        // The second key is cut just after a space, which MySQL compares as equal to the prefix without it.
        $entries = [
            'cutatlimit' => str_repeat('l', 255) . 'tail',
            'cutafterspace' => str_repeat('l', 254) . ' tail',
        ];

        foreach ($entries as $cn => $description) {
            $this->ldapClient()->create(new Entry(
                "cn={$cn},dc=foo,dc=bar",
                new Attribute('objectClass', 'top', 'inetOrgPerson'),
                new Attribute('cn', $cn),
                new Attribute('sn', 'Cut'),
                new Attribute('description', $description),
            ));
        }

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
            foreach (array_keys($entries) as $cn) {
                $this->ldapClient()->delete("cn={$cn},dc=foo,dc=bar");
            }
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
        $this->authenticateAdmin();
        $type = 'a' . str_repeat('b', Attribute::MAX_TYPE_LENGTH - 1);

        $this->ldapClient()->send(Operations::add(new Entry(
            'cn=longattr,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', 'longattr'),
            new Attribute('sn', 'Long'),
            new Attribute($type, 'value'),
        )));

        self::assertSame(
            'value',
            $this->ldapClient()->read('cn=longattr,dc=foo,dc=bar')?->get($type)?->firstValue(),
        );

        $this->ldapClient()->delete('cn=longattr,dc=foo,dc=bar');
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
