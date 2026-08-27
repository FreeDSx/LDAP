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

namespace FreeDSx\Ldap\Server\Backend\Storage\Filter;

/**
 * Why an assertion is Undefined before any entry is considered, for callers that answer differently per cause.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum UndefinedCause
{
    /**
     * The schema does not define the attribute description the assertion names.
     */
    case UnrecognizedAttributeType;

    /**
     * The assertion value is not one the attribute's syntax admits.
     */
    case InvalidAssertionValue;
}
