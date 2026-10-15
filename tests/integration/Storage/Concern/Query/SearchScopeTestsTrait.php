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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The search base and scope, including a malformed or missing base and the matched DN it answers with.
 */
trait SearchScopeTestsTrait
{
    /**
     * @param non-empty-string $baseDn
     */
    #[DataProvider('refusedBaseDnProvider')]
    public function testAMalformedBaseDnIsRefusedWithoutEndingTheSession(string $baseDn): void
    {
        $this->authenticateUser();
        $code = null;

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base($baseDn)
                    ->useBaseScope(),
            );
        } catch (OperationException $e) {
            $code = $e->getCode();
        }

        self::assertSame(
            ResultCode::INVALID_DN_SYNTAX,
            $code,
        );

        // A malformed DN names one message; the connection must stay usable for the next one.
        self::assertCount(
            1,
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useBaseScope(),
            ),
        );
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function refusedBaseDnProvider(): iterable
    {
        yield 'attribute type outside the grammar' => [
            '!!!=bar,dc=foo,dc=bar',
        ];
        yield 'attribute type with an inner space' => [
            'cn foo=bar,dc=foo,dc=bar',
        ];
        yield 'empty attribute type' => [
            '=bar,dc=foo,dc=bar',
        ];
        yield 'attribute option in an rdn' => [
            'cn;lang-en=alice,dc=foo,dc=bar',
        ];
        yield 'oid arc with a leading zero' => [
            '2.05.4.3=alice,dc=foo,dc=bar',
        ];
        yield 'hexstring value form' => [
            'cn=#0C03616263,dc=foo,dc=bar',
        ];
        yield 'raw null byte in a value' => [
            "cn=a\0b,dc=foo,dc=bar",
        ];
    }

    public function testSearchBaseObjectReturnsBaseEntry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame('dc=foo,dc=bar', $entries->first()?->getDn()->toString());
    }

    public function testSearchSingleLevelReturnsDirectChildrenOnly(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSingleLevelScope(),
        );

        self::assertCount(
            6,
            $entries,
        );
    }

    public function testSearchSubtreeWithFilterReturnsMatchingEntry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString(),
        );
    }

    public function testSearchWithNoMatchReturnsEmptyResult(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'nobody'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(0, $entries);
    }

    public function testMatchedDnIsEmptyOnASuccessfulSearch(): void
    {
        $this->authenticateUser();

        $response = $this->ldapClient()->send(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $done = $response?->getResponse();
        self::assertInstanceOf(
            SearchResultDone::class,
            $done,
        );
        self::assertSame(
            '',
            $done->getDn()->toString(),
        );
    }

    public function testMatchedDnNamesTheClosestAncestorWhenTheBaseIsMissing(): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=nope,ou=people,dc=foo,dc=bar')
                    ->useSubtreeScope(),
            );
            self::fail('The missing base should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::NO_SUCH_OBJECT,
                $e->getCode(),
            );
            self::assertSame(
                'ou=people,dc=foo,dc=bar',
                $e->getMatchedDn()?->toString(),
            );
        }
    }
}
