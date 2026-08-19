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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter;

use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * Translates FilterInterface into a SQL WHERE fragment.
 *
 * Returns null when untranslatable (PHP eval runs over the full candidate set), an exact SqlFilterResult when PHP eval
 * can be skipped, or a non-exact SqlFilterResult (superset) that still needs PHP eval over the reduced candidates.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface FilterTranslatorInterface
{
    public function translate(FilterInterface $filter): ?SqlFilterResult;
}
