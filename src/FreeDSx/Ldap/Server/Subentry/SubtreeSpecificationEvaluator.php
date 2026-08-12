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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;

/**
 * Decides whether a subtree specification covers an entry. RFC 3672.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubtreeSpecificationEvaluator
{
    public function __construct(
        private FilterEvaluatorInterface $filterEvaluator,
    ) {}

    /**
     * Whether the specification, read relative to its administrative point, selects the candidate.
     */
    public function covers(
        SubtreeSpecification $specification,
        Dn $administrativePoint,
        Entry $candidate,
    ): bool {
        $base = $this->absolute(
            $specification->base,
            $administrativePoint,
        );
        $candidateDn = $candidate->getDn();

        if (!$candidateDn->isDescendantOf($base)) {
            return false;
        }

        if (!$this->withinDepth($specification, $candidateDn, $base)) {
            return false;
        }

        if ($this->isChopped($specification, $candidateDn, $base)) {
            return false;
        }

        return $specification->specificationFilter === null
            || $this->filterEvaluator->evaluate($candidate, $specification->specificationFilter);
    }

    private function withinDepth(
        SubtreeSpecification $specification,
        Dn $candidateDn,
        Dn $base,
    ): bool {
        if ($specification->minimum === 0 && $specification->maximum === null) {
            return true;
        }

        $depth = $candidateDn->count() - $base->count();

        return $depth >= $specification->minimum
            && ($specification->maximum === null || $depth <= $specification->maximum);
    }

    /**
     * A chopBefore point is excluded along with everything beneath it; a chopAfter point is kept.
     */
    private function isChopped(
        SubtreeSpecification $specification,
        Dn $candidateDn,
        Dn $base,
    ): bool {
        foreach ($specification->chopBefore as $chop) {
            if ($candidateDn->isDescendantOf($this->absolute($chop, $base))) {
                return true;
            }
        }

        foreach ($specification->chopAfter as $chop) {
            $chopPoint = $this->absolute($chop, $base);

            if ($candidateDn->isDescendantOf($chopPoint) && !$candidateDn->equals($chopPoint)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A local name resolved against the name it is relative to.
     */
    private function absolute(
        Dn $relative,
        Dn $base,
    ): Dn {
        $name = $relative->toString();

        if ($name === '') {
            return $base;
        }

        $baseName = $base->toString();

        return $baseName === ''
            ? new Dn($name)
            : new Dn($name . ',' . $baseName);
    }
}
