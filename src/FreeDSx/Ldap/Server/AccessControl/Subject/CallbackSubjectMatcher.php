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

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\SubjectEvaluationException;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Throwable;

/**
 * Delegates subject matching to a user-supplied closure.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class CallbackSubjectMatcher implements TargetDependentSubjectInterface
{
    public function __construct(
        /** @var Closure(TokenInterface, Dn): bool */
        private readonly Closure $callback,
    ) {}

    public function matches(
        TokenInterface $token,
        ?Dn $targetDn,
    ): bool {
        // The closure is handed a target to judge, so it cannot be consulted without one.
        if ($targetDn === null) {
            return false;
        }

        try {
            return ($this->callback)($token, $targetDn);
        } catch (Throwable $cause) {
            throw new SubjectEvaluationException(
                'The subject callback could not decide whether it matches.',
                previous: $cause,
            );
        }
    }
}
