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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\SearchRequest;

/**
 * Shared helper methods for storage adapter implementations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait StorageAdapterTrait
{
    private function normalise(Dn $dn): string
    {
        return strtolower($dn->toString());
    }

    private function isInScope(
        string $normDn,
        string $normBase,
        int $scope,
    ): bool {
        return match ($scope) {
            SearchRequest::SCOPE_BASE_OBJECT => $normDn === $normBase,
            SearchRequest::SCOPE_SINGLE_LEVEL => $this->isDirectChild(
                $normDn,
                $normBase,
            ),
            SearchRequest::SCOPE_WHOLE_SUBTREE => $this->isAtOrBelow(
                $normDn,
                $normBase,
            ),
            default => false,
        };
    }

    private function isAtOrBelow(
        string $normDn,
        string $normBase,
    ): bool {
        if ($normDn === $normBase) {
            return true;
        }

        return str_ends_with(
            $normDn,
            ',' . $normBase
        );
    }

    private function isDirectChild(
        string $normDn,
        string $normBase,
    ): bool {
        if (!str_ends_with($normDn, ',' . $normBase)) {
            return false;
        }

        // Strip the base suffix and check there is exactly one RDN component left
        $prefix = substr(
            $normDn,
            0,
            strlen($normDn) - strlen(',' . $normBase)
        );

        return !str_contains($prefix, ',');
    }

}
