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

/**
 * Marks a subject whose answer depends on the target entry, so it can never match a rule that carries no target.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface TargetDependentSubjectInterface extends SubjectMatcherInterface {}
