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

/**
 * How faithfully SQL can answer an assertion on an attribute, which only the schema can decide.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum AttributeFilterSupport
{
    /**
     * The stored rows answer the assertion exactly.
     */
    case Exact;

    /**
     * The schema does not define the type, so every assertion on it is Undefined and no entry can match it, negated
     * or not (RFC 4511 4.5.1.7).
     */
    case NeverMatches;

    /**
     * Other types name this one as their SUP, so the rows for this name alone are an incomplete answer.
     */
    case NeedsEvaluator;
}
