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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;

use function in_array;
use function sprintf;

/**
 * Terminal step of the replay pipeline: applies the write the record describes, with no client to answer.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReplayWriteHandler implements MiddlewareHandlerInterface
{
    /**
     * Controls a replayed record can be given effect; a critical control outside this set has to be refused.
     */
    private const HONORED_CONTROLS = [
        // Names which delete the command factory builds.
        Control::OID_SUBTREE_DELETE,
        // Read off the write context by the storage backend.
        Control::OID_RELAX_RULES,
        // Evaluated ahead of this handler by AssertionMiddleware.
        Control::OID_ASSERTION,
        // Recognized server-wide and inert, since there are no referral entries to reinterpret.
        Control::OID_MANAGE_DSA_IT,
    ];

    public function __construct(private WriteRequestRouter $router) {}

    /**
     * @throws OperationException
     */
    public function handle(ServerRequestContext $context): ResponseStream
    {
        $controls = $context->message->controls();
        $this->assertAnswerable($controls);

        $this->router->route(
            $context->message->getRequest(),
            WriteContext::system(
                $context->tokenOrFail(),
                $controls,
            ),
        );

        return ResponseStream::of(
            [],
            WriteOperationResult::success(
                $context->message,
                new SchemaViolations(),
            ),
        );
    }

    /**
     * @throws OperationException
     */
    private function assertAnswerable(ControlBag $controls): void
    {
        foreach ($controls->toArray() as $control) {
            $oid = (string) $control->getTypeOid();

            if (!$control->getCriticality() || in_array($oid, self::HONORED_CONTROLS, true)) {
                continue;
            }

            throw new OperationException(
                sprintf('The "%s" control cannot be honored when replaying a change record.', $oid),
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            );
        }
    }
}
