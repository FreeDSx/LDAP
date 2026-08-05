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

namespace FreeDSx\Ldap\Server\AccessControl\Subject;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Determines whether a bound identity matches a rule subject.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SubjectMatcherInterface
{
    /**
     * @param ?Dn $targetDn The entry being operated on, or null for rules that carry no target.
     */
    public function matches(
        TokenInterface $token,
        ?Dn $targetDn,
    ): bool;
}
