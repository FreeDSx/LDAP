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

use FreeDSx\Ldap\Exception\SubtreeSpecificationParseException;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;

use function array_map;
use function get_class;
use function implode;
use function sprintf;

/**
 * Renders the filter tree a refinement parsed into back to its GSER form.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RefinementRenderer
{
    private function __construct() {}

    /**
     * @throws SubtreeSpecificationParseException if the filter is not a shape a refinement can express.
     */
    public static function render(FilterInterface $filter): string
    {
        if ($filter instanceof EqualityFilter) {
            return 'item:' . $filter->getValue();
        }

        if ($filter instanceof AndFilter) {
            return 'and:' . self::renderSet($filter->get());
        }

        if ($filter instanceof OrFilter) {
            return 'or:' . self::renderSet($filter->get());
        }

        if ($filter instanceof NotFilter) {
            return 'not:' . self::render($filter->get());
        }

        throw new SubtreeSpecificationParseException(sprintf(
            'A refinement cannot express a filter of type "%s".',
            get_class($filter),
        ));
    }

    /**
     * @param array<FilterInterface> $filters
     *
     * @throws SubtreeSpecificationParseException
     */
    private static function renderSet(array $filters): string
    {
        if ($filters === []) {
            return '{ }';
        }

        return sprintf(
            '{ %s }',
            implode(
                ', ',
                array_map(
                    static fn(FilterInterface $filter): string => self::render($filter),
                    $filters,
                ),
            ),
        );
    }
}
