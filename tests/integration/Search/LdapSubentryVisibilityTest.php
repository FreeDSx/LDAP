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

namespace Tests\Integration\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end RFC 3672 section 3 visibility.
 */
class LdapSubentryVisibilityTest extends ServerTestCase
{
    private const PEOPLE_DN = 'ou=people,dc=foo,dc=bar';

    private const BASE_DN = 'dc=foo,dc=bar';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-server',
            'tcp',
            static::storageExtraArgs(),
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();
    }

    public function test_subtree_search_omits_subentries_when_the_control_is_absent(): void
    {
        $this->authenticateUser();

        self::assertSame(
            [
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
                'cn=carol,ou=people,dc=foo,dc=bar',
                'ou=people,dc=foo,dc=bar',
            ],
            $this->searchDns(
                self::PEOPLE_DN,
                SearchRequest::SCOPE_WHOLE_SUBTREE,
            ),
        );
    }

    public function test_subtree_search_returns_only_subentries_when_the_control_is_true(): void
    {
        $this->authenticateUser();

        self::assertSame(
            ['cn=people-policy,ou=people,dc=foo,dc=bar'],
            $this->searchDns(
                self::PEOPLE_DN,
                SearchRequest::SCOPE_WHOLE_SUBTREE,
                Controls::subentries(true),
            ),
        );
    }

    public function test_subtree_search_omits_subentries_when_the_control_is_false(): void
    {
        $this->authenticateUser();

        self::assertSame(
            [
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
                'cn=carol,ou=people,dc=foo,dc=bar',
                'ou=people,dc=foo,dc=bar',
            ],
            $this->searchDns(
                self::PEOPLE_DN,
                SearchRequest::SCOPE_WHOLE_SUBTREE,
                Controls::subentries(false),
            ),
        );
    }

    public function test_single_level_search_omits_subentries_when_the_control_is_absent(): void
    {
        $this->authenticateUser();

        self::assertSame(
            [
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
                'cn=carol,ou=people,dc=foo,dc=bar',
            ],
            $this->searchDns(
                self::PEOPLE_DN,
                SearchRequest::SCOPE_SINGLE_LEVEL,
            ),
        );
    }

    public function test_single_level_search_returns_only_subentries_when_the_control_is_true(): void
    {
        $this->authenticateUser();

        self::assertSame(
            ['cn=people-policy,ou=people,dc=foo,dc=bar'],
            $this->searchDns(
                self::PEOPLE_DN,
                SearchRequest::SCOPE_SINGLE_LEVEL,
                Controls::subentries(true),
            ),
        );
    }

    public function test_base_scope_returns_a_subentry_without_the_control(): void
    {
        $this->authenticateUser();

        self::assertSame(
            ['cn=people-policy,ou=people,dc=foo,dc=bar'],
            $this->searchDns(
                'cn=people-policy,ou=people,dc=foo,dc=bar',
                SearchRequest::SCOPE_BASE_OBJECT,
            ),
        );
    }

    public function test_base_scope_returns_a_subentry_with_the_control(): void
    {
        $this->authenticateUser();

        self::assertSame(
            ['cn=people-policy,ou=people,dc=foo,dc=bar'],
            $this->searchDns(
                'cn=people-policy,ou=people,dc=foo,dc=bar',
                SearchRequest::SCOPE_BASE_OBJECT,
                Controls::subentries(true),
            ),
        );
    }

    public function test_the_control_is_accepted_rather_than_rejected_as_critical(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base(self::BASE_DN)
                ->useSubtreeScope(),
            Controls::subentries(true),
        );

        self::assertGreaterThan(
            0,
            count($entries),
        );
    }

    public function test_the_root_dse_advertises_the_control(): void
    {
        $rootDse = $this->ldapClient()->readOrFail('');

        self::assertContains(
            Control::OID_SUBENTRIES,
            $rootDse->get('supportedControl')?->getValues() ?? [],
        );
    }

    /**
     * The population is fixed for the whole paged session, so pages cannot mix the two.
     */
    public function test_paged_search_returns_only_subentries_across_pages(): void
    {
        $this->authenticateUser();

        $paging = $this->ldapClient()->paging(
            Operations::search(Filters::present('objectClass'))
                ->base(self::BASE_DN)
                ->useSubtreeScope(),
            1,
        );
        $paging->useControls(Controls::subentries(true));

        $dns = [];
        while ($paging->hasEntries()) {
            foreach ($paging->getEntries() as $entry) {
                $dns[] = $entry->getDn()->toString();
            }
        }

        sort($dns);

        self::assertSame(
            [
                'cn=people-policy,ou=people,dc=foo,dc=bar',
                'cn=root-policy,dc=foo,dc=bar',
            ],
            $dns,
        );
    }

    public function test_size_limit_is_not_consumed_by_hidden_subentries(): void
    {
        $this->authenticateUser();

        // Four ordinary entries sit in scope alongside one subentry.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base(self::PEOPLE_DN)
                ->useSubtreeScope()
                ->sizeLimit(4),
        );

        self::assertCount(
            4,
            $entries,
        );
    }

    /**
     * @return list<string>
     */
    protected static function storageExtraArgs(): array
    {
        return ['--seed=' . self::seedLdif()];
    }

    protected static function seedLdif(): string
    {
        return __DIR__ . '/../../resources/seed/subentry-seed.ldif';
    }

    /**
     * @return list<string>
     */
    private function searchDns(
        string $baseDn,
        int $scope,
        ?Control $control = null,
    ): array {
        $request = Operations::search(Filters::present('objectClass'))
            ->base($baseDn)
            ->setScope($scope);

        $controls = $control !== null
            ? [$control]
            : [];

        $dns = array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            iterator_to_array(
                $this->ldapClient()->search($request, ...$controls),
                false,
            ),
        );
        sort($dns);

        return $dns;
    }
}
