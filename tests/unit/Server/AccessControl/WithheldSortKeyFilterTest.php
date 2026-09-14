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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\WithheldAttributePolicy;
use FreeDSx\Ldap\Server\AccessControl\WithheldSortKeyFilter;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;

final class WithheldSortKeyFilterTest extends TestCase
{
    private WithheldSortKeyFilter $subject;

    private TokenInterface $token;

    protected function setUp(): void
    {
        // Core marks userPassword X-CONFIDENTIAL, so it is withheld from filters; cn and sn are not.
        $this->token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->subject = new WithheldSortKeyFilter(new WithheldAttributePolicy(
            new RuleBasedAccessControl(AclRules::fromEmpty()),
            SchemaResource::Core->load(),
        ));
    }

    public function test_a_key_on_a_withheld_attribute_is_dropped(): void
    {
        $control = new SortingControl(
            SortKey::ascending('userPassword'),
            SortKey::ascending('cn'),
        );

        $this->subject->stripWithheld(
            $control,
            $this->token,
        );

        self::assertSame(
            ['cn'],
            $this->attributesOf($control),
        );
    }

    public function test_a_control_of_only_withheld_keys_is_left_empty(): void
    {
        $control = new SortingControl(SortKey::ascending('userPassword'));

        $this->subject->stripWithheld(
            $control,
            $this->token,
        );

        self::assertSame(
            [],
            $control->getSortKeys(),
        );
    }

    public function test_keys_on_readable_attributes_are_left_untouched(): void
    {
        $control = new SortingControl(
            SortKey::descending('sn'),
            SortKey::ascending('cn'),
        );

        $this->subject->stripWithheld(
            $control,
            $this->token,
        );

        self::assertSame(
            ['sn', 'cn'],
            $this->attributesOf($control),
        );
    }

    public function test_it_preserves_the_order_and_direction_of_surviving_keys(): void
    {
        $control = new SortingControl(
            SortKey::descending('sn'),
            SortKey::ascending('userPassword'),
            SortKey::ascending('cn'),
        );

        $this->subject->stripWithheld(
            $control,
            $this->token,
        );

        $kept = $control->getSortKeys();
        self::assertSame(
            ['sn', 'cn'],
            $this->attributesOf($control),
        );
        self::assertTrue($kept[0]->getUseReverseOrder());
        self::assertFalse($kept[1]->getUseReverseOrder());
    }

    /**
     * @return list<string>
     */
    private function attributesOf(SortingControl $control): array
    {
        return array_values(array_map(
            static fn(SortKey $sortKey): string => $sortKey->getAttribute(),
            $control->getSortKeys(),
        ));
    }
}
