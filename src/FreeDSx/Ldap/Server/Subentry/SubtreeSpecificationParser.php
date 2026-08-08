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

namespace FreeDSx\Ldap\Server\Subentry;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\SubtreeSpecificationParseException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;

use function sprintf;

/**
 * Parses the GSER subtree specification syntax, 1.3.6.1.4.1.1466.115.121.1.45. RFC 3672.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SubtreeSpecificationParser
{
    private const BASE = 'base';

    private const SPECIFIC_EXCLUSIONS = 'specificExclusions';

    private const MINIMUM = 'minimum';

    private const MAXIMUM = 'maximum';

    private const SPECIFICATION_FILTER = 'specificationFilter';

    private const CHOP_BEFORE = 'chopBefore';

    private const CHOP_AFTER = 'chopAfter';

    private const ITEM = 'item';

    private const AND = 'and';

    private const OR = 'or';

    private const NOT = 'not';

    /**
     * @throws SubtreeSpecificationParseException
     */
    public function parse(string $specification): SubtreeSpecification
    {
        $reader = new SubtreeSpecificationReader($specification);
        $parsed = $this->readSpecification($reader);

        if (!$reader->atEnd()) {
            $reader->error('Unexpected trailing content');
        }

        return $parsed;
    }

    /**
     * @throws SubtreeSpecificationParseException
     */
    private function readSpecification(SubtreeSpecificationReader $reader): SubtreeSpecification
    {
        $reader->expect('{');

        $base = new Dn('');
        $chopBefore = [];
        $chopAfter = [];
        $minimum = 0;
        $maximum = null;
        $filter = null;
        $seen = [];

        while (!$reader->isNext('}')) {
            if ($reader->atEnd()) {
                $reader->error('Unterminated specification, expected "}"');
            }

            $at = $reader->offset();
            $identifier = $reader->readBareToken();
            $this->claim($reader, $seen, $identifier, $at);

            match ($identifier) {
                self::BASE => $base = new Dn($reader->readString()),
                self::SPECIFIC_EXCLUSIONS => [$chopBefore, $chopAfter] = $this->readExclusions($reader),
                self::MINIMUM => $minimum = $reader->readInteger(),
                self::MAXIMUM => $maximum = $reader->readInteger(),
                self::SPECIFICATION_FILTER => $filter = $this->readRefinement($reader),
                default => $reader->error(
                    sprintf('Unknown component "%s"', $identifier),
                    $at,
                ),
            };

            if (!$reader->consumeIf(',')) {
                break;
            }
        }

        $reader->expect('}');
        $this->assertDepthsOrdered($reader, $minimum, $maximum);

        return new SubtreeSpecification(
            base: $base,
            chopBefore: $chopBefore,
            chopAfter: $chopAfter,
            minimum: $minimum,
            maximum: $maximum,
            specificationFilter: $filter,
        );
    }

    /**
     * @return array{list<Dn>, list<Dn>} The chopBefore and chopAfter points, in that order.
     *
     * @throws SubtreeSpecificationParseException
     */
    private function readExclusions(SubtreeSpecificationReader $reader): array
    {
        $reader->expect('{');

        $before = [];
        $after = [];

        while (!$reader->isNext('}')) {
            if ($reader->atEnd()) {
                $reader->error('Unterminated exclusions, expected "}"');
            }

            $at = $reader->offset();
            $keyword = $reader->readBareToken();
            $reader->expect(':');

            match ($keyword) {
                self::CHOP_BEFORE => $before[] = new Dn($reader->readString()),
                self::CHOP_AFTER => $after[] = new Dn($reader->readString()),
                default => $reader->error(
                    sprintf('Unknown exclusion "%s"', $keyword),
                    $at,
                ),
            };

            if (!$reader->consumeIf(',')) {
                break;
            }
        }

        $reader->expect('}');

        return [$before, $after];
    }

    /**
     * A refinement is an assertion over object classes, so it maps onto the ordinary filter types.
     *
     * @throws SubtreeSpecificationParseException
     */
    private function readRefinement(SubtreeSpecificationReader $reader): FilterInterface
    {
        $at = $reader->offset();
        $keyword = $reader->readBareToken();
        $reader->expect(':');

        return match ($keyword) {
            self::ITEM => new EqualityFilter(
                AttributeTypeOid::NAME_OBJECT_CLASS,
                $reader->readBareToken(),
            ),
            self::AND => new AndFilter(...$this->readRefinementSet($reader)),
            self::OR => new OrFilter(...$this->readRefinementSet($reader)),
            self::NOT => new NotFilter($this->readRefinement($reader)),
            default => $reader->error(
                sprintf('Unknown refinement "%s"', $keyword),
                $at,
            ),
        };
    }

    /**
     * @return list<FilterInterface>
     *
     * @throws SubtreeSpecificationParseException
     */
    private function readRefinementSet(SubtreeSpecificationReader $reader): array
    {
        $reader->expect('{');

        $refinements = [];
        while (!$reader->isNext('}')) {
            if ($reader->atEnd()) {
                $reader->error('Unterminated refinement set, expected "}"');
            }

            $refinements[] = $this->readRefinement($reader);

            if (!$reader->consumeIf(',')) {
                break;
            }
        }
        $reader->expect('}');

        return $refinements;
    }

    /**
     * @param array<string, true> $seen
     *
     * @throws SubtreeSpecificationParseException
     */
    private function claim(
        SubtreeSpecificationReader $reader,
        array &$seen,
        string $identifier,
        int $at,
    ): void {
        if (isset($seen[$identifier])) {
            $reader->error(
                sprintf('Duplicate component "%s"', $identifier),
                $at,
            );
        }

        $seen[$identifier] = true;
    }

    /**
     * @throws SubtreeSpecificationParseException
     */
    private function assertDepthsOrdered(
        SubtreeSpecificationReader $reader,
        int $minimum,
        ?int $maximum,
    ): void {
        if ($maximum !== null && $maximum < $minimum) {
            $reader->error(sprintf(
                'The maximum depth %d is below the minimum depth %d',
                $maximum,
                $minimum,
            ));
        }
    }
}
