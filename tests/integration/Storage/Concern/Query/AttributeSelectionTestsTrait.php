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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Which attributes a search returns: requested types, options, supertypes, operational attributes, and typesOnly.
 */
trait AttributeSelectionTestsTrait
{
    public function testRequestingABaseTypeReturnsItsTaggedVariants(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'mail')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $alice = $entries->first();
        self::assertNotNull($alice);
        self::assertSame(
            ['alice@foo.bar'],
            $alice->get(new Attribute('mail'), true)?->getValues(),
        );
        self::assertSame(
            ['alice-en@foo.bar'],
            $alice->get(new Attribute('mail;lang-en'), true)?->getValues(),
        );
    }

    public function testRequestingEntryDnReturnsTheEntryDn(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'entryDN')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            $entries->first()?->get(new Attribute('entryDN'), true)?->getValues(),
        );
    }

    public function testRequestingAllOperationalAttributesReturnsEntryDn(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), '+')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            $entries->first()?->get(new Attribute('entryDN'), true)?->getValues(),
        );
    }

    public function testRequestingEntryDnByItsOidReturnsIt(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), '1.3.6.1.1.20')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            $entries->first()?->get(new Attribute('entryDN'), true)?->getValues(),
        );
    }

    public function testRequestingSubschemaSubentryReturnsTheSubschemaDn(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'subschemaSubentry')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=Subschema'],
            $entries->first()?->get(new Attribute('subschemaSubentry'), true)?->getValues(),
        );
    }

    public function testSubschemaSubentryIsReturnedOnABaseScopedRead(): void
    {
        $this->authenticateUser();

        // The discovery flow every schema-aware client uses: read it from the entry it governs.
        $entries = $this->ldapClient()->search(
            Operations::read('cn=alice,ou=people,dc=foo,dc=bar', 'subschemaSubentry'),
        );

        self::assertSame(
            ['cn=Subschema'],
            $entries->first()?->get(new Attribute('subschemaSubentry'), true)?->getValues(),
        );
    }

    public function testRequestingAllOperationalAttributesReturnsSubschemaSubentry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), '+')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=Subschema'],
            $entries->first()?->get(new Attribute('subschemaSubentry'), true)?->getValues(),
        );
    }

    public function testSubschemaSubentryIsOperationalSoItIsNotReturnedByDefault(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertNull(
            $entries->first()?->get(new Attribute('subschemaSubentry'), true),
        );
    }

    public function testEntryDnIsReturnedOnABaseScopedRead(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::read('cn=alice,ou=people,dc=foo,dc=bar', 'entryDN'),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            $entries->first()?->get(new Attribute('entryDN'), true)?->getValues(),
        );
    }

    public function testEntryDnIsOperationalSoItIsNotReturnedByDefault(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertNull(
            $entries->first()?->get(new Attribute('entryDN'), true),
        );
    }

    public function testRequestingASupertypeReturnsItsSubtypeValues(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'name')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $alice = $entries->first();
        self::assertNotNull($alice);
        self::assertSame(
            ['alice'],
            $alice->get(new Attribute('cn'), true)?->getValues(),
        );
        self::assertSame(
            ['Smith'],
            $alice->get(new Attribute('sn'), true)?->getValues(),
        );
    }

    public function testRequestingATypeByItsOidReturnsIt(): void
    {
        $this->authenticateUser();

        // Filtering on a different attribute, so only the OID can be what asks for cn.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Smith'), '2.5.4.3')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['alice'],
            $entries->first()?->get(new Attribute('cn'), true)?->getValues(),
        );
    }

    public function testATypesOnlyRequestKeepsAttributeOptions(): void
    {
        $this->authenticateUser();

        $request = Operations::search(Filters::equal('cn', 'alice'), 'mail')
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();
        $request->setAttributesOnly(true);

        $alice = $this->ldapClient()->search($request)->first();
        self::assertNotNull($alice);

        $descriptions = array_map(
            static fn(Attribute $attribute): string => $attribute->getDescription(),
            $alice->getAttributes(),
        );
        sort($descriptions);
        self::assertSame(
            ['mail', 'mail;lang-de;lang-en', 'mail;lang-en'],
            $descriptions,
        );
    }

    /**
     * RFC 4512 2.5.2.1: naming a subset of the options selects the descriptions carrying at least those.
     */
    public function testRequestingAnOptionSubsetReturnsTheDescriptionsCarryingMore(): void
    {
        $this->authenticateUser();

        $alice = $this->searchSelecting(
            'alice',
            'mail;lang-de',
        );
        self::assertNotNull($alice);

        self::assertSame(
            ['mail;lang-de;lang-en'],
            $this->descriptionsOf($alice),
        );
    }

    public function testRequestingAnOptionTheDescriptionLacksReturnsNothing(): void
    {
        $this->authenticateUser();

        $alice = $this->searchSelecting(
            'alice',
            'mail;lang-fr',
        );
        self::assertNotNull($alice);

        self::assertSame(
            [],
            $this->descriptionsOf($alice),
        );
    }

    /**
     * A supertype description must not be returned for a request naming one of its subtypes.
     */
    public function testRequestingATaggedDescriptionDoesNotReturnTheUntaggedOne(): void
    {
        $this->authenticateUser();

        $alice = $this->searchSelecting(
            'alice',
            'mail;lang-en',
        );
        self::assertNotNull($alice);

        self::assertSame(
            ['mail;lang-de;lang-en', 'mail;lang-en'],
            $this->descriptionsOf($alice),
        );
    }

    public function testSearchReturnsAttributeValues(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $alice = $entries->first();
        self::assertNotNull($alice);
        self::assertSame(['Smith'], $alice->get('sn')?->getValues());
    }

    public function testSearchTypesOnlyReturnsAttributeNamesWithoutValues(): void
    {
        $this->authenticateUser();

        $request = Operations::search(Filters::equal('cn', 'alice'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();
        $request->setAttributesOnly(true);

        $entries = $this->ldapClient()->search($request);

        $alice = $entries->first();
        self::assertNotNull($alice);
        // sn attribute should be present but with no values
        $sn = $alice->get('sn');
        self::assertNotNull($sn);
        self::assertEmpty($sn->getValues());
    }

    public function testInexactFilterOnUnrequestedAttributeStillMatchesAndProjects(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=hazard,dc=foo,dc=bar',
            [
                'cn' => 'hazard',
                'sn' => 'Smithers',
                'mail' => 'hazard@foo.bar',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        // Substring is inexact: SQL yields candidates and PHP re-evaluates (sn) on the hydrated entry, so storage must
        // materialize sn (filter-referenced) even though only cn was requested; projection then drops it.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::contains('sn', 'mither'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->select('cn'),
        );

        $entry = $entries->first();
        self::assertNotNull($entry);
        self::assertSame(
            'cn=hazard,dc=foo,dc=bar',
            $entry->getDn()->toString(),
        );
        self::assertSame(
            ['hazard'],
            $entry->get(new Attribute('cn'), true)?->getValues(),
        );
        self::assertNull($entry->get(new Attribute('sn'), true));
    }

    public function testNoAttributesRequestStillMatchesAnInexactFilter(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=noattr,dc=foo,dc=bar',
            [
                'cn' => 'noattr',
                'sn' => 'Jones',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::contains('sn', 'one'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->select('1.1'),
        );

        $entry = $entries->first();
        self::assertNotNull($entry);
        self::assertSame(
            'cn=noattr,dc=foo,dc=bar',
            $entry->getDn()->toString(),
        );
        self::assertCount(
            0,
            $entry->getAttributes(),
        );
    }

    private function searchSelecting(
        string $cn,
        string $selector,
    ): ?Entry {
        return $this->ldapClient()->search(
            Operations::search(
                Filters::equal('cn', $cn),
                $selector,
            )
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        )->first();
    }

    /**
     * @return list<string>
     */
    private function descriptionsOf(Entry $entry): array
    {
        $descriptions = array_map(
            static fn(Attribute $attribute): string => $attribute->getDescription(),
            $entry->getAttributes(),
        );
        sort($descriptions);

        return $descriptions;
    }
}
