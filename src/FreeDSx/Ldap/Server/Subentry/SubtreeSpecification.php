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
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use Stringable;

use function array_map;
use function implode;
use function sprintf;
use function str_replace;

/**
 * The portion of a subtree a subentry applies to, relative to its administrative point. RFC 3672.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubtreeSpecification implements Stringable
{
    /**
     * @param list<Dn> $chopBefore Chop points excluded along with everything beneath them.
     * @param list<Dn> $chopAfter Chop points retained, with everything beneath them excluded.
     * @param ?int $maximum Depth below the base to stop at, or null when unbounded.
     * @param ?FilterInterface $specificationFilter Object class refinement, or null when unrefined.
     */
    public function __construct(
        public Dn $base = new Dn(''),
        public array $chopBefore = [],
        public array $chopAfter = [],
        public int $minimum = 0,
        public ?int $maximum = null,
        public ?FilterInterface $specificationFilter = null,
    ) {}

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * The GSER form, which round-trips through the parser.
     */
    public function toString(): string
    {
        $components = [];

        if ($this->base->toString() !== '') {
            $components[] = 'base ' . self::quote($this->base->toString());
        }

        $exclusions = $this->exclusionComponents();
        if ($exclusions !== []) {
            $components[] = 'specificExclusions { ' . implode(', ', $exclusions) . ' }';
        }

        if ($this->minimum !== 0) {
            $components[] = 'minimum ' . $this->minimum;
        }

        if ($this->maximum !== null) {
            $components[] = 'maximum ' . $this->maximum;
        }

        if ($this->specificationFilter !== null) {
            $components[] = 'specificationFilter ' . RefinementRenderer::render($this->specificationFilter);
        }

        return $components === []
            ? '{ }'
            : sprintf(
                '{ %s }',
                implode(', ', $components),
            );
    }

    /**
     * @return list<string>
     */
    private function exclusionComponents(): array
    {
        $before = array_map(
            static fn(Dn $dn): string => 'chopBefore:' . self::quote($dn->toString()),
            $this->chopBefore,
        );
        $after = array_map(
            static fn(Dn $dn): string => 'chopAfter:' . self::quote($dn->toString()),
            $this->chopAfter,
        );

        return [
            ...$before,
            ...$after,
        ];
    }

    /**
     * A GSER character string, in which a literal quote is doubled.
     */
    private static function quote(string $value): string
    {
        return sprintf(
            '"%s"',
            str_replace('"', '""', $value),
        );
    }
}
