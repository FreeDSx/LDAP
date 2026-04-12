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

namespace Tests\Unit\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;
use PHPUnit\Framework\TestCase;

class DnTest extends TestCase
{
    private Dn $subject;

    protected function setUp(): void
    {
        $this->subject = new Dn('cn=fo\,o, dc=local,dc=example');
    }

    public function test_it_should_get_all_pieces_as_an_array_of_RDNs(): void
    {
        self::assertEquals(
            [
                new Rdn("cn", "fo\,o"),
                new Rdn("dc", "local"),
                new Rdn("dc", "example"),
            ],
            $this->subject->toArray(),
        );
    }

    public function test_it_should_get_the_parent_dn(): void
    {
        self::assertEquals(
            new Dn('dc=local,dc=example'),
            $this->subject->getParent(),
        );
    }

    public function test_it_should_get_the_rdn(): void
    {
        self::assertEquals(
            new Rdn('cn', 'fo\,o'),
            $this->subject->getRdn(),
        );
    }

    public function test_it_should_return_a_count(): void
    {
        self::assertEquals(
            3,
            $this->subject->count()
        );
    }

    public function test_it_should_get_the_string_representation(): void
    {
        self::assertSame(
            'cn=fo\,o, dc=local,dc=example',
            $this->subject->toString(),
        );
    }

    public function test_it_should_check_if_it_is_a_valid_dn(): void
    {
        self::assertTrue(Dn::isValid('cn=foo,dc=bar,dc=foo'));
        self::assertFalse(Dn::isValid('foo'));
        self::assertTrue(Dn::isValid(''));
    }

    public function test_it_should_handle_a_rootdse_as_a_dn(): void
    {
        $this->subject = new Dn('');

        self::assertSame(
            '',
            $this->subject->toString(),
        );
        self::assertSame(
            [],
            $this->subject->toArray(),
        );
        self::assertCount(
            0,
            $this->subject,
        );
        self::assertNull($this->subject->getParent());
    }

    public function test_normalize_returns_lowercased_copy(): void
    {
        $dn = new Dn('CN=Alice,DC=Example,DC=Com');
        $normalized = $dn->normalize();

        self::assertSame(
            'cn=alice,dc=example,dc=com',
            $normalized->toString(),
        );
        self::assertSame(
            'CN=Alice,DC=Example,DC=Com',
            $dn->toString(),
        );
    }

    public function test_is_child_of_returns_true_for_direct_child(): void
    {
        $child = new Dn('cn=alice,dc=example,dc=com');

        self::assertTrue(
            $child->isChildOf(new Dn('dc=example,dc=com')),
        );
    }

    public function test_is_child_of_returns_false_for_grandchild(): void
    {
        $grandchild = new Dn('cn=alice,ou=people,dc=example,dc=com');

        self::assertFalse(
            $grandchild->isChildOf(new Dn('dc=example,dc=com')),
        );
    }

    public function test_is_child_of_returns_false_for_unrelated_dn(): void
    {
        $dn = new Dn('cn=alice,dc=other,dc=com');

        self::assertFalse(
            $dn->isChildOf(new Dn('dc=example,dc=com')),
        );
    }

    public function test_is_child_of_root_returns_true_for_single_component_dn(): void
    {
        self::assertTrue(
            (new Dn('dc=com'))->isChildOf(new Dn('')),
        );
    }

    public function test_is_child_of_root_returns_false_for_multi_component_dn(): void
    {
        self::assertFalse(
            (new Dn('dc=example,dc=com'))->isChildOf(new Dn('')),
        );
    }

    public function test_is_child_of_is_case_insensitive(): void
    {
        self::assertTrue(
            (new Dn('cn=alice,dc=example,dc=com'))->isChildOf(new Dn('DC=EXAMPLE,DC=COM')),
        );
    }

    public function test_is_child_of_handles_escaped_comma_in_rdn_value(): void
    {
        $child = new Dn('cn=fo\,o,dc=local,dc=example');

        self::assertTrue(
            $child->isChildOf(new Dn('dc=local,dc=example')),
        );
    }

    public function test_is_descendant_of_returns_true_for_direct_child(): void
    {
        self::assertTrue(
            (new Dn('cn=alice,dc=example,dc=com'))->isDescendantOf(new Dn('dc=example,dc=com')),
        );
    }

    public function test_is_descendant_of_returns_true_for_grandchild(): void
    {
        self::assertTrue(
            (new Dn('cn=alice,ou=people,dc=example,dc=com'))->isDescendantOf(new Dn('dc=example,dc=com')),
        );
    }

    public function test_is_descendant_of_returns_true_for_identical_dn(): void
    {
        self::assertTrue(
            (new Dn('dc=example,dc=com'))->isDescendantOf(new Dn('dc=example,dc=com')),
        );
    }

    public function test_is_descendant_of_is_case_insensitive(): void
    {
        self::assertTrue(
            (new Dn('cn=alice,dc=example,dc=com'))->isDescendantOf(new Dn('DC=EXAMPLE,DC=COM')),
        );
    }

    public function test_is_descendant_of_returns_false_for_unrelated_dn(): void
    {
        self::assertFalse(
            (new Dn('cn=alice,dc=other,dc=org'))->isDescendantOf(new Dn('dc=example,dc=com')),
        );
    }

    public function test_is_descendant_of_returns_false_for_parent_dn(): void
    {
        self::assertFalse(
            (new Dn('dc=example,dc=com'))->isDescendantOf(new Dn('cn=alice,dc=example,dc=com')),
        );
    }

    public function test_is_descendant_of_empty_base_matches_any_non_empty_dn(): void
    {
        self::assertTrue(
            (new Dn('dc=com'))->isDescendantOf(new Dn('')),
        );
        self::assertTrue(
            (new Dn('cn=alice,dc=example,dc=com'))->isDescendantOf(new Dn('')),
        );
    }

    public function test_is_descendant_of_empty_dn_against_empty_base_is_false(): void
    {
        self::assertFalse(
            (new Dn(''))->isDescendantOf(new Dn('')),
        );
    }

    public function test_is_descendant_of_rejects_string_suffix_collision_from_escaped_comma(): void
    {
        // The entry parent is "dc=example,dc=com". A naive str_ends_with against
        // ",John,dc=example,dc=com" would be true and let this entry slip into
        // a subtree search whose base is "John,dc=example,dc=com".
        $entry = new Dn('cn=Doe\,John,dc=example,dc=com');

        self::assertFalse(
            $entry->isDescendantOf(new Dn('John,dc=example,dc=com')),
        );
        self::assertTrue(
            $entry->isDescendantOf(new Dn('dc=example,dc=com')),
        );
    }
}
