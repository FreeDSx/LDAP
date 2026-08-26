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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Evaluates an RFC 4528 assertion control against the operation's target entry.
 *
 * The outcome is observable, so an assertion on an attribute the identity may not read would otherwise answer a
 * question it may not ask. Matching against the readable entry makes a withheld attribute assert as absent, exactly
 * as it does on the search path.
 *
 * Whether the target may be read at all is authorized before this runs.
 *
 * @see \FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware::authorizeControlledReads()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AssertionEvaluator
{
    public function __construct(
        private FilterEvaluatorInterface $filterEvaluator,
        private ReadBackendInterface $backend,
        private AccessControlInterface $accessControl,
    ) {}

    /**
     * Throws ASSERTION_FAILED when an assertion control is present and its filter does not match the target entry.
     *
     * @throws OperationException
     */
    public function assertSatisfied(
        Dn $targetDn,
        ControlBag $controls,
        TokenInterface $token,
    ): void {
        $control = $controls->get(Control::OID_ASSERTION);

        if (!$control instanceof AssertionControl) {
            return;
        }

        $entry = $this->backend->get($targetDn);

        if ($entry === null) {
            return;
        }

        $readable = $this->accessControl->stripUnreadableAttributes(
            $token,
            $entry,
        );

        if ($this->filterEvaluator->evaluate($readable, $control->getFilter())) {
            return;
        }

        throw new OperationException(
            'The assertion control filter did not match the target entry.',
            ResultCode::ASSERTION_FAILED,
        );
    }
}
