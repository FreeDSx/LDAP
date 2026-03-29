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
 * Holds an ordered list of write handlers and routes each write command to
 * the first handler that declares support for it.
 *
 * Handlers are tried in registration order. Explicitly registered handlers
 * take priority when the backend is appended last as a fallback.
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
