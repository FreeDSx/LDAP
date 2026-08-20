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

namespace Tests\Unit\FreeDSx\Ldap\Server\Subentry;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use FreeDSx\Ldap\Server\Subentry\SubtreeSpecificationEvaluator;
use FreeDSx\Ldap\Server\Subentry\SubtreeSpecificationParser;
use PHPUnit\Framework\TestCase;

final class SubtreeSpecificationEvaluatorTest extends TestCase
{
    use ServerContainerTrait;

    private const ADMIN_POINT = 'ou=area,dc=foo,dc=bar';

    private SubtreeSpecificationEvaluator $subject;

    private SubtreeSpecificationParser $parser;

    protected function setUp(): void
    {
        $this->subject = new SubtreeSpecificationEvaluator(
            $this->fromContainer(FilterEvaluatorInterface::class),
        );
        $this->parser = new SubtreeSpecificationParser();
    }

    public function test_an_empty_specification_covers_the_administrative_point_itself(): void
    {
        self::assertTrue($this->covers('{ }', self::ADMIN_POINT));
    }

    public function test_an_empty_specification_covers_everything_beneath(): void
    {
        self::assertTrue($this->covers('{ }', 'cn=deep,ou=people,' . self::ADMIN_POINT));
    }

    public function test_it_does_not_cover_entries_outside_the_administrative_point(): void
    {
        self::assertFalse($this->covers('{ }', 'cn=elsewhere,dc=foo,dc=bar'));
    }

    /**
     * The base is a local name, so it resolves against the administrative point.
     */
    public function test_a_base_narrows_to_that_branch(): void
    {
        self::assertTrue($this->covers('{ base "ou=people" }', 'cn=alice,ou=people,' . self::ADMIN_POINT));
        self::assertFalse($this->covers('{ base "ou=people" }', 'cn=bob,ou=other,' . self::ADMIN_POINT));
    }

    public function test_a_minimum_excludes_entries_above_it(): void
    {
        $specification = '{ minimum 1 }';

        self::assertFalse($this->covers($specification, self::ADMIN_POINT));
        self::assertTrue($this->covers($specification, 'ou=people,' . self::ADMIN_POINT));
        self::assertTrue($this->covers($specification, 'cn=alice,ou=people,' . self::ADMIN_POINT));
    }

    public function test_a_maximum_excludes_entries_below_it(): void
    {
        $specification = '{ maximum 1 }';

        self::assertTrue($this->covers($specification, self::ADMIN_POINT));
        self::assertTrue($this->covers($specification, 'ou=people,' . self::ADMIN_POINT));
        self::assertFalse($this->covers($specification, 'cn=alice,ou=people,' . self::ADMIN_POINT));
    }

    public function test_depth_is_measured_from_the_base_not_the_administrative_point(): void
    {
        $specification = '{ base "ou=people", maximum 0 }';

        self::assertTrue($this->covers($specification, 'ou=people,' . self::ADMIN_POINT));
        self::assertFalse($this->covers($specification, 'cn=alice,ou=people,' . self::ADMIN_POINT));
    }

    /**
     * The chop point itself is excluded along with everything beneath it.
     */
    public function test_chop_before_excludes_the_chop_point(): void
    {
        $specification = '{ specificExclusions { chopBefore:"ou=hidden" } }';

        self::assertFalse($this->covers($specification, 'ou=hidden,' . self::ADMIN_POINT));
        self::assertFalse($this->covers($specification, 'cn=alice,ou=hidden,' . self::ADMIN_POINT));
        self::assertTrue($this->covers($specification, 'ou=shown,' . self::ADMIN_POINT));
    }

    /**
     * The chop point is kept; only what sits beneath it is excluded.
     */
    public function test_chop_after_keeps_the_chop_point(): void
    {
        $specification = '{ specificExclusions { chopAfter:"ou=edge" } }';

        self::assertTrue($this->covers($specification, 'ou=edge,' . self::ADMIN_POINT));
        self::assertFalse($this->covers($specification, 'cn=alice,ou=edge,' . self::ADMIN_POINT));
        self::assertTrue($this->covers($specification, 'ou=other,' . self::ADMIN_POINT));
    }

    /**
     * Had the chop resolved against the administrative point instead, this branch would not be chopped.
     */
    public function test_chop_points_resolve_against_the_base(): void
    {
        $specification = '{ base "ou=people", specificExclusions { chopBefore:"ou=temps" } }';

        self::assertFalse($this->covers($specification, 'ou=temps,ou=people,' . self::ADMIN_POINT));
        self::assertTrue($this->covers($specification, 'ou=staff,ou=people,' . self::ADMIN_POINT));
    }

    public function test_a_refinement_selects_on_object_class(): void
    {
        $specification = '{ specificationFilter item:inetOrgPerson }';

        self::assertTrue($this->covers(
            $specification,
            'cn=alice,' . self::ADMIN_POINT,
            ['objectClass' => 'inetOrgPerson'],
        ));
        self::assertFalse($this->covers(
            $specification,
            'ou=people,' . self::ADMIN_POINT,
            ['objectClass' => 'organizationalUnit'],
        ));
    }

    public function test_a_negated_refinement_excludes_the_named_class(): void
    {
        $specification = '{ specificationFilter not:item:device }';

        self::assertFalse($this->covers(
            $specification,
            'cn=printer,' . self::ADMIN_POINT,
            ['objectClass' => 'device'],
        ));
        self::assertTrue($this->covers(
            $specification,
            'cn=alice,' . self::ADMIN_POINT,
            ['objectClass' => 'inetOrgPerson'],
        ));
    }

    public function test_every_component_must_hold_at_once(): void
    {
        $specification = '{ base "ou=people", specificExclusions { chopBefore:"ou=temps" }, '
            . 'minimum 1, maximum 2, specificationFilter item:inetOrgPerson }';
        $attributes = ['objectClass' => 'inetOrgPerson'];

        self::assertTrue($this->covers(
            $specification,
            'cn=alice,ou=people,' . self::ADMIN_POINT,
            $attributes,
        ));
        // Excluded by the chop.
        self::assertFalse($this->covers(
            $specification,
            'cn=temp,ou=temps,ou=people,' . self::ADMIN_POINT,
            $attributes,
        ));
        // Excluded by the minimum.
        self::assertFalse($this->covers(
            $specification,
            'ou=people,' . self::ADMIN_POINT,
            $attributes,
        ));
        // Excluded by the refinement.
        self::assertFalse($this->covers(
            $specification,
            'cn=printer,ou=people,' . self::ADMIN_POINT,
            ['objectClass' => 'device'],
        ));
    }

    /**
     * @param array<string, string> $attributes
     */
    private function covers(
        string $specification,
        string $candidateDn,
        array $attributes = [],
    ): bool {
        return $this->subject->covers(
            $this->parser->parse($specification),
            new Dn(self::ADMIN_POINT),
            Entry::fromArray($candidateDn, $attributes),
        );
    }
}
