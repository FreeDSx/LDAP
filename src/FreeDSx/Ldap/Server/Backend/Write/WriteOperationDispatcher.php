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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;

/**
 * Routes a write command to the first registered handler that supports it; explicit handlers precede the fallback backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WriteOperationDispatcher
{
    /**
     * @var WriteHandlerInterface[]
     */
    private array $handlers;

    public function __construct(WriteHandlerInterface ...$handlers)
    {
        $this->handlers = $handlers;
    }

    /**
     * @throws OperationException
     */
    public function dispatch(WriteRequestInterface $request): void
    {
        foreach ($this->handlers as $handler) {
            if ($handler->supports($request)) {
                $handler->handle($request);

                return;
            }
        }

        throw new OperationException(
            'This operation is not supported.',
            ResultCode::UNWILLING_TO_PERFORM
        );
    }
}
