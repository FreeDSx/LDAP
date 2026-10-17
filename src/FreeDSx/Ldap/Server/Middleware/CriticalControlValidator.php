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
use FreeDSx\Ldap\Operation\Request\RequestInterface;
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
    public function assertSupportedForRequest(
        RequestInterface $request,
        HandlerId $routeId,
        ControlBag $controls,
    ): void {
        if (!$this->controlRegistry->appliesTo($routeId)) {
            return;
        }

        $this->assertControls(
            $controls,
            $this->controlRegistry->supportedControlsFor(
                $routeId,
                $request,
            ),
        );
    }

    /**
     * @throws OperationException
     */
    public function assertSupportedForBind(ControlBag $controls): void
    {
        $this->assertControls(
            $controls,
            $this->controlRegistry->supportedControlsForBind(),
        );
    }

    /**
     * @param list<string> $supported
     *
     * @throws OperationException
     */
    private function assertControls(
        ControlBag $controls,
        array $supported,
    ): void {
        $this->assertNoCriticalUnsupportedControls(
            $controls,
            $supported,
        );
        $this->assertNoRepeatedControls(
            $controls,
            $supported,
        );
    }

    /**
     * RFC 4511 4.1.11: no supported control defines a meaning for a repeated copy.
     *
     * @param list<string> $supported
     *
     * @throws OperationException
     */
    private function assertNoRepeatedControls(
        ControlBag $controls,
        array $supported,
    ): void {
        $seen = [];

        foreach ($controls as $control) {
            $oid = $control->getTypeOid();

            // Copies of a control the operation ignores are ignored with it.
            if (!in_array($oid, $supported, true)) {
                continue;
            }

            if (isset($seen[$oid])) {
                throw new OperationException(
                    sprintf(
                        'The control %s is specified more than once.',
                        $oid,
                    ),
                    ResultCode::PROTOCOL_ERROR,
                );
            }
            $seen[$oid] = true;
        }
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
