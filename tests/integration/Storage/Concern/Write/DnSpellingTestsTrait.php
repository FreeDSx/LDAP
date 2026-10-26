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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * How a DN is spelled: escapes, encodings, invisible code points, case, and naming values held under another spelling.
 */
trait DnSpellingTestsTrait
{
    public function testDnsDifferingOnlyByAccentAreDistinctEntries(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=josé,dc=foo,dc=bar',
                ['cn' => 'josé', 'sn' => 'Accented', 'objectClass' => 'inetOrgPerson'],
            ));
            $admin->create(Entry::fromArray(
                'cn=jose,dc=foo,dc=bar',
                ['cn' => 'jose', 'sn' => 'Plain', 'objectClass' => 'inetOrgPerson'],
            ));
        });

        $accented = $this->ldapClient()->read('cn=josé,dc=foo,dc=bar');
        $plain = $this->ldapClient()->read('cn=jose,dc=foo,dc=bar');

        self::assertSame(
            'Accented',
            $accented?->get('sn')?->firstValue(),
            'An accent-folding DN collation resolves this lookup to the wrong entry.',
        );
        self::assertSame(
            'Plain',
            $plain?->get('sn')?->firstValue(),
        );
    }

    public function testABindDoesNotSucceedUnderADnSpellingTheDirectoryDoesNotHold(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=rené,dc=foo,dc=bar',
            [
                'cn' => 'rené',
                'sn' => 'Accented',
                'userPassword' => '12345',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->expectException(BindException::class);

        $this->ldapClient()->bind(
            'cn=rene,dc=foo,dc=bar',
            '12345',
        );
    }

    public function testAddIsRefusedWhenAHexpairEscapeLeavesTheDnWithoutAUtf8CanonicalForm(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_DN_SYNTAX);

        $this->ldapClient()->create(Entry::fromArray(
            'userPassword=\FF,dc=foo,dc=bar',
            [
                'userPassword' => "\xFF",
                'cn' => 'poison',
                'sn' => 'Poison',
                'objectClass' => 'inetOrgPerson',
            ],
        ));
    }

    public function testRenameIsRefusedWhenAHexpairEscapeLeavesTheDnWithoutAUtf8CanonicalForm(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=repoison,dc=foo,dc=bar',
            ['cn' => 'repoison', 'sn' => 'Repoison', 'objectClass' => 'inetOrgPerson'],
        ));

        try {
            $this->ldapClient()->rename('cn=repoison,dc=foo,dc=bar', 'userPassword=\FF', true);
            self::fail('A new RDN with no UTF-8 canonical form should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }
        $this->authenticateUser();

        self::assertNotNull($this->ldapClient()->read('cn=repoison,dc=foo,dc=bar'));
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=repoison,dc=foo,dc=bar'));
    }

    public function testDeletingTheRdnValueUnderAnEquivalentSpellingIsRefused(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=Foo Bar,dc=foo,dc=bar',
            [
                'cn' => ['Foo Bar', 'Alias Name'],
                'sn' => 'Bar',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        try {
            // caseIgnoreMatch folds the repeated space, so this names the value giving the entry its DN.
            $this->ldapClient()->send(Operations::modify(
                'cn=Foo Bar,dc=foo,dc=bar',
                Change::delete(new Attribute('cn', 'Foo  Bar')),
            ));
            self::fail('Removing the naming value under an equivalent spelling should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::NOT_ALLOWED_ON_RDN,
                $e->getCode(),
            );
        }
        $this->authenticateUser();

        $entry = $this->ldapClient()->read('cn=Foo Bar,dc=foo,dc=bar');
        self::assertContains(
            'Foo Bar',
            $entry?->get('cn')?->getValues() ?? [],
            'The entry must still hold the value its DN names.',
        );
    }

    public function testDeletingAnEscapedRdnValueIsRefused(): void
    {
        $this->authenticateAdmin();

        // A second value keeps schema validation out of it, leaving the RDN guard as the only thing that can refuse.
        $this->ldapClient()->create(Entry::fromArray(
            'cn=Doe\\, Jane,dc=foo,dc=bar',
            [
                'cn' => ['Doe, Jane', 'Janey'],
                'sn' => 'Doe',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        try {
            $this->ldapClient()->send(Operations::modify(
                'cn=Doe\\, Jane,dc=foo,dc=bar',
                Change::delete(new Attribute('cn', 'Doe, Jane')),
            ));
            self::fail('Removing the naming value should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::NOT_ALLOWED_ON_RDN,
                $e->getCode(),
            );
        }
    }

    public function testRenameToANewRdnThatIsNotUtf8IsRefused(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->rename(
                'cn=alice,ou=people,dc=foo,dc=bar',
                "cn=\xFF\xFE",
            );
            self::fail('The new RDN that is not UTF-8 should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }
        $this->authenticateUser();

        self::assertCount(
            1,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('cn', 'alice'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );
    }

    public function testAddWithAHexstringDnIsRefused(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->create(Entry::fromArray(
                'cn=#0C03616263,dc=foo,dc=bar',
                [
                    'cn' => 'abc',
                    'sn' => 'Hex',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));
            self::fail('The hexstring DN form should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }
    }

    public function testAddWithAnEscapedLeadingSharpIsStoredAsALiteralValue(): void
    {
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            'cn=\23hashtag,dc=foo,dc=bar',
            [
                'cn' => '#hashtag',
                'sn' => 'Hash',
                'objectClass' => 'inetOrgPerson',
            ],
        )));

        try {
            $entries = $this->ldapClient()->search(
                Operations::search(Filters::equal('cn', '#hashtag'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            );

            self::assertCount(1, $entries);
        } finally {
            $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=\23hashtag,dc=foo,dc=bar'));
        }
    }

    /**
     * RDN values are folded case-insensitively whatever the attribute's EQUALITY rule says, so labeledURI names
     * one entry despite matching case-exactly everywhere else.
     *
     * A deliberate deviation: honouring caseExact here would make DNs differing only in case distinct entries, and
     * an accidental case difference is likelier than an intended one. Real world implementations genuinely already
     * behave differently on this point.
     */
    public function testRdnCaseIsFoldedEvenForACaseExactAttribute(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'labeledURI=CaseTest,dc=foo,dc=bar',
            [
                'cn' => 'casetest',
                'sn' => 'Case',
                'labeledURI' => 'CaseTest',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        try {
            $this->ldapClient()->create(Entry::fromArray(
                'labeledURI=casetest,dc=foo,dc=bar',
                [
                    'cn' => 'casetest2',
                    'sn' => 'Case',
                    'labeledURI' => 'casetest',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));
            self::fail('The case-folded DN should have named the entry already added.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ENTRY_ALREADY_EXISTS,
                $e->getCode(),
            );
        } finally {
            $this->ldapClient()->delete('labeledURI=CaseTest,dc=foo,dc=bar');
        }
    }

    /**
     * @param non-empty-string $cn
     */
    #[DataProvider('invisiblyDifferentValueProvider')]
    public function testAddIsRefusedForADnDifferingOnlyByACodePointThatRendersAsNothing(string $cn): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->ldapClient()->create(Entry::fromArray("cn=$cn,dc=foo,dc=bar", [
            'cn' => $cn,
            'sn' => 'Impostor',
            'objectClass' => 'inetOrgPerson',
        ]));
    }

    /**
     * RFC 4518 2.2 maps these to nothing, so each names the seeded cn=admin and cannot be added beside it.
     *
     * @return iterable<string, array{non-empty-string}>
     */
    public static function invisiblyDifferentValueProvider(): iterable
    {
        yield 'left to right mark' => [
            "adm\u{200E}in",
        ];
        yield 'right to left mark' => [
            "adm\u{200F}in",
        ];
        yield 'soft hyphen' => [
            "adm\u{00AD}in",
        ];
        yield 'zero width space' => [
            "adm\u{200B}in",
        ];
        yield 'object replacement character' => [
            "adm\u{FFFC}in",
        ];
        yield 'ascii control' => [
            "adm\x01in",
        ];
    }

    public function testARenameOntoAnInvisiblyDifferentDnIsRefused(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        // Renaming keeps the parent, so this lands beside the seeded cn=admin under dc=foo,dc=bar.
        $this->ldapClient()->rename(
            'cn=nosn,dc=foo,dc=bar',
            "cn=adm\u{200E}in",
        );
    }

    public function testAddAcceptsANamingValueTheEntryHoldsUnderAnEquivalentSpelling(): void
    {
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            'cn=Über,dc=foo,dc=bar',
            ['cn' => 'über', 'sn' => 'Uber', 'objectClass' => 'inetOrgPerson'],
        )));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn')
                ->base('cn=Über,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['über'],
            $found->first()?->get('cn')?->getValues(),
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=Über,dc=foo,dc=bar'));
    }

    public function testRenameThroughARespelledDnRemovesTheStoredNamingValue(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=École,dc=foo,dc=bar',
                ['cn' => 'École', 'sn' => 'Ecole', 'objectClass' => 'inetOrgPerson'],
            ));
            $admin->rename(
                'cn=école,dc=foo,dc=bar',
                'cn=ecole2',
                true,
            );
        });

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn')
                ->base('cn=ecole2,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['ecole2'],
            $found->first()?->get('cn')?->getValues(),
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=ecole2,dc=foo,dc=bar'));
    }

    public function testRenameKeepsCaseVariantsOfACaseExactNamingValue(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'labeledURI=Xyz,dc=foo,dc=bar',
                [
                    'cn' => 'variants',
                    'sn' => 'Variants',
                    'labeledURI' => ['Xyz', 'xyz', 'XYZ'],
                    'objectClass' => 'inetOrgPerson',
                ],
            ));
            $admin->rename(
                'labeledURI=Xyz,dc=foo,dc=bar',
                'cn=variants',
                true,
            );
        });

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'labeledURI')
                ->base('cn=variants,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['xyz', 'XYZ'],
            $found->first()?->get('labeledURI')?->getValues(),
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=variants,dc=foo,dc=bar'));
    }

    public function testRenameCanRespellTheRdnInADifferentCase(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=Recase,dc=foo,dc=bar',
                ['cn' => 'Recase', 'sn' => 'Recase', 'objectClass' => 'inetOrgPerson'],
            ));
            $admin->rename(
                'cn=Recase,dc=foo,dc=bar',
                'cn=recase',
                true,
            );
        });

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn')
                ->base('cn=recase,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['recase'],
            $found->first()?->get('cn')?->getValues(),
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=recase,dc=foo,dc=bar'));
    }

    public function testAHexEscapeNamesTheSameEntryAsTheCharacterItEncodes(): void
    {
        $this->authenticateUser();

        // RFC 4514 4: \61 is the hex escape for "a", so this base denotes cn=alice.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('cn=\61lice,ou=people,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertSame(
            ['alice'],
            $entries->first()?->get(new Attribute('cn'), true)?->getValues(),
        );
    }

    public function testBothSpellingsOfAnEscapedCommaNameOneEntry(): void
    {
        $this->authenticateUser();

        // The seed holds cn=Smith\, John; \2c is the hex spelling of the same escaped comma.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('cn=Smith\2c John,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertSame(
            ['Smith, John'],
            $entries->first()?->get(new Attribute('cn'), true)?->getValues(),
        );
    }

    public function testAnAddUnderAMissingParentMatchesTheAncestorAsTheRequestSpelledIt(): void
    {
        self::assertSame(
            'OU=People,DC=Foo,DC=Bar',
            $this->matchedDnOf(Operations::add(Entry::fromArray(
                'cn=orphan,OU=Missing,OU=People,DC=Foo,DC=Bar',
                [
                    'objectClass' => 'person',
                    'cn' => 'orphan',
                    'sn' => 'Orphan',
                ],
            ))),
        );
    }

    public function testAModifyOfAMissingEntryMatchesTheParentAsTheRequestSpelledIt(): void
    {
        self::assertSame(
            'OU=People,DC=Foo,DC=Bar',
            $this->matchedDnOf(Operations::modify(
                'cn=missing,OU=People,DC=Foo,DC=Bar',
                Change::replace(
                    'description',
                    'changed',
                ),
            )),
        );
    }

    public function testADeleteOfAMissingEntryMatchesTheParentAsTheRequestSpelledIt(): void
    {
        self::assertSame(
            'OU=People,DC=Foo,DC=Bar',
            $this->matchedDnOf(Operations::delete('cn=missing,OU=People,DC=Foo,DC=Bar')),
        );
    }

    public function testARenameOfAMissingEntryMatchesTheParentAsTheRequestSpelledIt(): void
    {
        self::assertSame(
            'OU=People,DC=Foo,DC=Bar',
            $this->matchedDnOf(Operations::rename(
                'cn=missing,OU=People,DC=Foo,DC=Bar',
                'cn=renamed',
            )),
        );
    }

    public function testAMoveUnderAMissingSuperiorMatchesItsAncestorAsTheRequestSpelledIt(): void
    {
        self::assertSame(
            'OU=People,DC=Foo,DC=Bar',
            $this->matchedDnOf(Operations::move(
                'cn=user,dc=foo,dc=bar',
                'OU=Missing,OU=People,DC=Foo,DC=Bar',
            )),
        );
    }

    private function matchedDnOf(RequestInterface $request): ?string
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->send($request);
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::NO_SUCH_OBJECT,
                $e->getCode(),
            );

            return $e->getMatchedDn()?->toString();
        }

        self::fail('The request should have been refused as naming no such object.');
    }
}
