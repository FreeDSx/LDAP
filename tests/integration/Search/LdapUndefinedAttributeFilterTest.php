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

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * RFC 4511 §4.5.1.7: an assertion on an attribute type the schema does not define is Undefined whether
 * an entry happens to store values under that name.
 */
class LdapUndefinedAttributeFilterTest extends ServerTestCase
{
    private const SEED = __DIR__ . '/../../resources/seed/undefined-attribute-seed.ldif';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-ldif=' . self::SEED,
                '--no-seed-validation',
            ],
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

    /**
     * @return iterable<string, array{FilterInterface}>
     */
    public static function undefinedAttributeFilterProvider(): iterable
    {
        yield 'equality on the stored value' => [
            Filters::equal(
                'shoeSize',
                '12',
            ),
        ];
        yield 'negated equality on the stored value' => [
            Filters::not(Filters::equal(
                'shoeSize',
                '12',
            )),
        ];
        yield 'present' => [
            Filters::present('shoeSize'),
        ];
        yield 'negated present' => [
            Filters::not(Filters::present('shoeSize')),
        ];
    }

    #[DataProvider('undefinedAttributeFilterProvider')]
    public function testAnUndefinedTypeAnEntryStoresIsAlwaysUndefined(FilterInterface $filter): void
    {
        $this->authenticateUser();

        self::assertCount(
            0,
            $this->ldapClient()->search(
                Operations::search($filter)
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );
    }

    public function testTheFixtureEntryReallyStoresTheUndefinedAttribute(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'undefined'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            ['12'],
            $entries->first()?->get('shoeSize')?->getValues(),
            'Without the stored value the Undefined cases above would pass vacuously.',
        );
    }

    /**
     * Hook for subclasses to route the shared server through a different backend.
     *
     * @return list<string>
     */
    protected static function storageExtraArgs(): array
    {
        return [];
    }
}
