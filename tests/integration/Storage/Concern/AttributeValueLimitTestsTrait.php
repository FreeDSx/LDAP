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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * The cap on how many values one attribute may hold, over a server configured low enough to reach it.
 */
trait AttributeValueLimitTestsTrait
{
    public function testAnAddBeyondTheValueLimitIsRefused(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->create($this->boundedEntry(
            'limit-add-over',
            self::SHARED_MAX_ATTRIBUTE_VALUES + 1,
        ));
    }

    public function testAnAddAtTheValueLimitIsStoredWhole(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create($this->boundedEntry(
            'limit-add-at',
            self::SHARED_MAX_ATTRIBUTE_VALUES,
        ));

        self::assertCount(
            self::SHARED_MAX_ATTRIBUTE_VALUES,
            $this->boundedValuesOf('limit-add-at'),
        );
    }

    public function testAModifyCrossingTheValueLimitIsRefused(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create($this->boundedEntry(
            'limit-modify-over',
            self::SHARED_MAX_ATTRIBUTE_VALUES,
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->send(Operations::modify(
            'cn=limit-modify-over,dc=foo,dc=bar',
            Change::add('description', 'one too many'),
        ));
    }

    public function testAModifyRefusedByTheValueLimitLeavesTheEntryAsItWas(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create($this->boundedEntry(
            'limit-modify-intact',
            self::SHARED_MAX_ATTRIBUTE_VALUES,
        ));

        try {
            $this->ldapClient()->send(Operations::modify(
                'cn=limit-modify-intact,dc=foo,dc=bar',
                Change::add('description', 'one too many'),
            ));
            self::fail('The modify should have been refused.');
        } catch (OperationException) {
        }

        $stored = $this->boundedValuesOf('limit-modify-intact');

        self::assertCount(
            self::SHARED_MAX_ATTRIBUTE_VALUES,
            $stored,
        );
        self::assertNotContains(
            'one too many',
            $stored,
        );
    }

    public function testAModifyStayingWithinTheValueLimitIsApplied(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create($this->boundedEntry(
            'limit-modify-under',
            self::SHARED_MAX_ATTRIBUTE_VALUES - 1,
        ));

        $this->ldapClient()->send(Operations::modify(
            'cn=limit-modify-under,dc=foo,dc=bar',
            Change::add('description', 'one more'),
        ));

        self::assertCount(
            self::SHARED_MAX_ATTRIBUTE_VALUES,
            $this->boundedValuesOf('limit-modify-under'),
        );
    }

    public function testAnEntryRefusedByTheValueLimitIsNotStoredAtAll(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->create($this->boundedEntry(
                'limit-add-absent',
                self::SHARED_MAX_ATTRIBUTE_VALUES + 1,
            ));
            self::fail('The add should have been refused.');
        } catch (OperationException) {
        }

        self::assertCount(
            0,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('cn', 'limit-add-absent'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );
    }

    public function testTheValueLimitRefusalNamesTheAttributeAndTheLimitButNoValue(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->create(new Entry(
                'cn=limit-message,dc=foo,dc=bar',
                new Attribute('objectClass', 'top', 'inetOrgPerson'),
                new Attribute('cn', 'limit-message'),
                new Attribute('sn', 'Message'),
                new Attribute('description', ...self::boundedValues(self::SHARED_MAX_ATTRIBUTE_VALUES + 1)),
            ));
            self::fail('The add should have been refused.');
        } catch (OperationException $e) {
            self::assertStringContainsString('description', $e->getMessage());
            self::assertStringContainsString(
                (string) self::SHARED_MAX_ATTRIBUTE_VALUES,
                $e->getMessage(),
            );
            self::assertStringNotContainsString('bounded value 1', $e->getMessage());
        }
    }

    private function boundedEntry(
        string $cn,
        int $count,
    ): Entry {
        return new Entry(
            "cn={$cn},dc=foo,dc=bar",
            new Attribute('objectClass', 'top', 'inetOrgPerson'),
            new Attribute('cn', $cn),
            new Attribute('sn', 'Bounded'),
            new Attribute('description', ...self::boundedValues($count)),
        );
    }

    /**
     * @return list<string>
     */
    private function boundedValuesOf(string $cn): array
    {
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', $cn), 'description')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        return array_values($entries->first()?->get('description')?->getValues() ?? []);
    }

    /**
     * @return list<string>
     */
    private static function boundedValues(int $count): array
    {
        return array_map(
            static fn(int $i): string => "bounded value {$i}",
            range(1, $count),
        );
    }
}
