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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;

use function in_array;
use function sprintf;

/**
 * The RFC 4511 §4.1.11 check, shared by the pipeline and by the bind.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CriticalControlValidator
{
    public function __construct(private ServerControlRegistry $controlRegistry = new ServerControlRegistry()) {}

    /**
     * @throws OperationException
     */
    public function assertSupportedForRoute(
        HandlerId $routeId,
        ControlBag $controls,
    ): void {
        if (!$this->controlRegistry->appliesTo($routeId)) {
            return;
        }

        $this->assertNoCriticalUnsupportedControls(
            $controls,
            $this->controlRegistry->supportedControlsFor($routeId),
        );
    }

    /**
     * @throws OperationException
     */
    public function assertSupportedForBind(ControlBag $controls): void
    {
        $this->assertNoCriticalUnsupportedControls(
            $controls,
            $this->controlRegistry->supportedControlsForBind(),
        );
    }

    /**
     * @param list<string> $supported
     *
     * @throws OperationException
     */
    private function assertNoCriticalUnsupportedControls(
        ControlBag $controls,
        array $supported,
    ): void {
        foreach ($controls as $control) {
            if (!$control->getCriticality()) {
                continue;
            }

            if (!in_array($control->getTypeOid(), $supported, true)) {
                throw new OperationException(
                    sprintf('Critical control %s is not supported.', $control->getTypeOid()),
                    ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                );
            }
        }
    }
}
