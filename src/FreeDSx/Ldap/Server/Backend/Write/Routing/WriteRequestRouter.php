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

namespace FreeDSx\Ldap\Server\Backend\Write\Routing;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;

/**
 * Turns a protocol request into the write it describes, and hands it to whatever performs it.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteRequestRouter
{
    public function __construct(
        private WriteHandlerInterface $writes,
        private WriteCommandFactory $commandFactory = new WriteCommandFactory(),
    ) {}

    /**
     * @throws OperationException
     */
    public function route(
        RequestInterface $request,
        WriteContext $context,
    ): void {
        $this->writes->handle(
            $this->commandFactory->fromRequest(
                $request,
                $context,
            ),
            $context,
        );
    }
}
