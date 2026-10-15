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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Dereferencing an alias named as the search base, and the aliasProblem a broken alias answers with.
 */
trait AliasDereferencingTestsTrait
{
    /**
     * A base naming an alias resolves to the entry it names (RFC 4511 4.5.1.3 derefFindingBaseObj), while an alias
     * met while searching is returned as the ordinary entry it is rather than failing the search.
     */
    public function testAliasDereferencing(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', static::storageExtraArgs());
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray('cn=ref,dc=foo,dc=bar', [
            'objectClass' => ['top', 'alias', 'extensibleObject'],
            'cn' => 'ref',
            'aliasedObjectName' => 'cn=user,dc=foo,dc=bar',
        ]));

        try {
            self::assertCount(
                1,
                $this->ldapClient()->search(
                    Operations::search(Filters::equal('cn', 'ref'))
                        ->base('dc=foo,dc=bar')
                        ->useSubtreeScope(),
                ),
                'An alias in scope is an ordinary entry when nothing is dereferenced.',
            );

            self::assertCount(
                1,
                $this->ldapClient()->search(
                    Operations::search(Filters::equal('cn', 'ref'))
                        ->base('dc=foo,dc=bar')
                        ->useSubtreeScope()
                        ->setDereferenceAliases(SearchRequest::DEREF_ALWAYS),
                ),
                'An alias in scope stays an ordinary entry rather than failing the search.',
            );

            $viaAlias = $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=ref,dc=foo,dc=bar')
                    ->useBaseScope()
                    ->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT),
            );

            self::assertSame(
                'cn=user,dc=foo,dc=bar',
                strtolower((string) $viaAlias->first()?->getDn()),
                'A base naming an alias resolves to the entry it names.',
            );

            self::assertSame(
                'cn=ref,dc=foo,dc=bar',
                strtolower((string) $this->ldapClient()->search(
                    Operations::search(Filters::present('objectClass'))
                        ->base('cn=ref,dc=foo,dc=bar')
                        ->useBaseScope(),
                )->first()?->getDn()),
                'The same base names the alias itself when nothing is dereferenced.',
            );
        } finally {
            $this->ldapClient()->delete('cn=ref,dc=foo,dc=bar');
        }
    }

    public function testABaseAliasWhoseClassAndTargetAreSpelledByOidAndAliasIsDereferenced(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', static::storageExtraArgs());
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray('cn=oid-ref,dc=foo,dc=bar', [
            'objectClass' => ['top', '2.5.6.1', 'extensibleObject'],
            'cn' => 'oid-ref',
            'aliasedObjectName' => 'commonName=user,dc=foo,dc=bar',
        ]));

        try {
            $viaAlias = $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=oid-ref,dc=foo,dc=bar')
                    ->useBaseScope()
                    ->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT),
            );

            self::assertSame(
                'cn=user,dc=foo,dc=bar',
                strtolower((string) $viaAlias->first()?->getDn()),
            );
        } finally {
            $this->ldapClient()->delete('cn=oid-ref,dc=foo,dc=bar');
        }
    }

    public function testABaseAliasNamingAMissingEntryIsAnAliasProblem(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', static::storageExtraArgs());
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray('cn=dangle,dc=foo,dc=bar', [
            'objectClass' => ['top', 'alias', 'extensibleObject'],
            'cn' => 'dangle',
            'aliasedObjectName' => 'cn=nothere,dc=foo,dc=bar',
        ]));

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=dangle,dc=foo,dc=bar')
                    ->useBaseScope()
                    ->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT),
            );
            self::fail('Expected the dangling alias to be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ALIAS_PROBLEM,
                $e->getCode(),
            );
            self::assertSame(
                'cn=dangle,dc=foo,dc=bar',
                $e->getMatchedDn()?->toString(),
            );
        } finally {
            $this->ldapClient()->delete('cn=dangle,dc=foo,dc=bar');
        }
    }

    public function testABaseAliasThatLoopsIsAnAliasProblem(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', static::storageExtraArgs());
        $this->authenticateAdmin();

        foreach ([['loopa', 'loopb'], ['loopb', 'loopa']] as [$name, $target]) {
            $this->ldapClient()->create(Entry::fromArray("cn=$name,dc=foo,dc=bar", [
                'objectClass' => ['top', 'alias', 'extensibleObject'],
                'cn' => $name,
                'aliasedObjectName' => "cn=$target,dc=foo,dc=bar",
            ]));
        }

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=loopa,dc=foo,dc=bar')
                    ->useBaseScope()
                    ->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT),
            );
            self::fail('Expected the alias loop to be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ALIAS_PROBLEM,
                $e->getCode(),
            );
            self::assertContains(
                $e->getMatchedDn()?->toString(),
                [
                    'cn=loopa,dc=foo,dc=bar',
                    'cn=loopb,dc=foo,dc=bar',
                ],
            );
        } finally {
            $this->ldapClient()->delete('cn=loopa,dc=foo,dc=bar');
            $this->ldapClient()->delete('cn=loopb,dc=foo,dc=bar');
        }
    }
}
