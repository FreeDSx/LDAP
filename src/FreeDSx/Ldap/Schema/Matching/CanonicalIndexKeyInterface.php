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

namespace FreeDSx\Ldap\Schema\Matching;

/**
 * A rule whose index key is canonical: values sharing a key are equal under it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface CanonicalIndexKeyInterface extends IndexableComparatorInterface {}
