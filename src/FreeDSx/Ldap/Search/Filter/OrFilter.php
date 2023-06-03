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

namespace FreeDSx\Ldap\Search\Filter;

use Countable;
use IteratorAggregate;
use Stringable;

/**
 * Represents a logical 'or' filter. RFC 4511, 4.5.1
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OrFilter implements FilterContainerInterface, IteratorAggregate, Countable, Stringable
{
    use FilterContainerTrait;

    protected const FILTER_OPERATOR = self::OPERATOR_OR;

    protected const CHOICE_TAG = 1;
}
