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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SubtreeSpecificationParseException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;

use function iterator_to_array;
use function sprintf;

/**
 * Finds the subentries that govern an entry, by walking its ancestry for administrative points. RFC 3672.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class GoverningSubentryResolver
{
    public function __construct(
        private ReadBackendInterface $backend,
        private SubtreeSpecificationEvaluator $evaluator,
        private SubtreeSpecificationParser $parser = new SubtreeSpecificationParser(),
    ) {}

    /**
     * The subentries whose specification covers the entry, nearest administrative point first.
     *
     * @return list<Entry>
     *
     * @throws OperationException
     */
    public function govern(Entry $entry): array
    {
        $governing = [];

        // The entry may itself be an administrative point, so the walk starts at its own DN.
        for ($current = $entry->getDn(); $current !== null; $current = $current->getParent()) {
            $administrativePoint = $current->normalize();

            foreach ($this->subentriesUnder($administrativePoint) as $subentry) {
                if ($this->covers($subentry, $administrativePoint, $entry)) {
                    $governing[] = $subentry;
                }
            }
        }

        return $governing;
    }

    /**
     * @throws OperationException
     */
    private function covers(
        Entry $subentry,
        Dn $administrativePoint,
        Entry $entry,
    ): bool {
        $value = $subentry
            ->get(AttributeTypeOid::NAME_SUBTREE_SPECIFICATION)
            ?->firstValue();

        if ($value === null) {
            return false;
        }

        return $this->evaluator->covers(
            $this->parse($value),
            $administrativePoint,
            $entry,
        );
    }

    /**
     * @throws OperationException
     */
    private function parse(string $value): SubtreeSpecification
    {
        try {
            return $this->parser->parse($value);
        } catch (SubtreeSpecificationParseException $e) {
            // Declining to guess: a stored value that cannot be read leaves the governing set undecidable.
            throw new OperationException(
                sprintf(
                    'A stored "%s" value could not be parsed.',
                    AttributeTypeOid::NAME_SUBTREE_SPECIFICATION,
                ),
                ResultCode::OTHER,
                $e,
            );
        }
    }

    /**
     * @return list<Entry>
     *
     * @throws OperationException
     */
    private function subentriesUnder(Dn $administrativePoint): array
    {
        $entry = $this->backend->get($administrativePoint);

        if ($entry === null || !$this->isAdministrativePoint($entry)) {
            return [];
        }

        // RFC 3672 places subentries directly below the administrative point, so one level is enough.
        $request = (new SearchRequest(Filters::present(AttributeTypeOid::NAME_OBJECT_CLASS)))
            ->base($administrativePoint)
            ->useSingleLevelScope();

        /** @var list<Entry> $subentries */
        $subentries = iterator_to_array(
            $this->backend->search(
                $request,
                SubentryVisibility::Only,
                new ControlBag(),
            )->entries(),
            false,
        );

        return $subentries;
    }

    private function isAdministrativePoint(Entry $entry): bool
    {
        return ($entry->get(AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE)?->getValues() ?? []) !== [];
    }
}
