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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use Generator;

/**
 * Answers reads over a pluggable EntryStorageInterface, applying the LDAP semantics storage knows nothing about.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WritableStorageBackend implements LdapBackendInterface, ResettableInterface
{
    public function __construct(
        private readonly EntryStorageInterface $storage,
        private readonly SearchStreamBuilder $searchStream,
        private readonly StorageListOptionsFactory $listOptions,
        private readonly FilterEvaluatorInterface $filterEvaluator,
        private readonly EntryLocator $locator,
    ) {}

    public function reset(): void
    {
        if ($this->storage instanceof ResettableInterface) {
            $this->storage->reset();
        }
    }

    public function get(Dn $dn): ?Entry
    {
        return $this->storage->find($dn->normalize());
    }

    /**
     * @throws OperationException
     */
    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool {
        $entry = $this->get($dn);

        if ($entry === null) {
            $this->locator->throwNoSuchObject($dn);
        }

        // A comparison is an equality assertion, so it answers through the same evaluation a filter would get.
        return $this->filterEvaluator->evaluate(
            $entry,
            $filter,
        );
    }

    /**
     * @throws OperationException
     */
    public function search(
        SearchRequest $request,
        SubentryVisibility $subentries,
        ControlBag $controls = new ControlBag(),
        ?SearchLimits $effectiveLimits = null,
        ?PageSlice $slice = null,
    ): EntryStream {
        $baseDn = $request->getBaseDn() ?? new Dn('');
        $normBase = $baseDn->normalize();

        if ($request->getScope() === SearchRequest::SCOPE_BASE_OBJECT) {
            return $this->searchBaseObject(
                $normBase,
                $baseDn,
                $request,
            );
        }

        $this->assertSearchBaseExists(
            $normBase,
            $baseDn,
        );

        $options = $this->listOptions->make(
            $request,
            $normBase,
            $controls,
            $subentries,
            $effectiveLimits,
            $slice,
        );

        try {
            $stream = $this->storage->list($options);
        } catch (InvalidAttributeException) {
            # RFC 4511 §4.5.1.7: unrecognized attribute descriptions evaluate to Undefined; yield zero entries.
            return new EntryStream((static function (): Generator {
                yield from [];

                return null;
            })());
        }

        return $this->searchStream->buildForList(
            $stream,
            $request,
            $effectiveLimits,
        );
    }

    /**
     * A base scope search addresses one entry, so it bypasses the list options entirely.
     *
     * @throws OperationException
     */
    private function searchBaseObject(
        Dn $normBase,
        Dn $baseDn,
        SearchRequest $request,
    ): EntryStream {
        $entry = $this->storage->find($normBase);

        if ($entry === null) {
            $this->locator->throwNoSuchObject($baseDn);
        }

        return $this->searchStream->buildForBaseObject(
            $entry,
            $request,
        );
    }

    /**
     * The RootDSE is an empty base, and is answered elsewhere.
     *
     * @throws OperationException
     */
    private function assertSearchBaseExists(
        Dn $normBase,
        Dn $baseDn,
    ): void {
        if ($normBase->toString() === '') {
            return;
        }

        if (!$this->storage->exists($normBase)) {
            $this->locator->throwNoSuchObject($baseDn);
        }
    }
}
