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

namespace FreeDSx\Ldap\Server\AccessControl\Rule;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\AccessControl\Subject\TargetDependentSubjectInterface;

/**
 * Shared guard for rules that are answered with no entry in hand.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait TargetlessSubjectTrait
{
    /**
     * @throws InvalidArgumentException when the subject could only be decided against an entry.
     */
    private static function assertSubjectNeedsNoTarget(SubjectMatcherInterface $subject): void
    {
        if (!$subject instanceof TargetDependentSubjectInterface) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            '%s carries no target entry, so it cannot use the %s subject.',
            static::class,
            $subject::class,
        ));
    }
}
