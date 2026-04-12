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
 * Translates an LDAP FilterInterface into a SQL fragment for use in a WHERE clause.
 *
 * Return values:
 *   - null                             — filter cannot be expressed in SQL; all in-scope
 *                                        entries are returned; PHP eval must run over the
 *                                        full candidate set.
 *   - SqlFilterResult (isExact: true)  — the SQL exactly captures the filter semantics;
 *                                        PHP eval can safely be skipped for these entries.
 *   - SqlFilterResult (isExact: false) — partial SQL (superset); PHP eval still runs
 *                                        but only over the already-reduced candidate set.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface FilterTranslatorInterface
{
    public function translate(FilterInterface $filter): ?SqlFilterResult;
}
