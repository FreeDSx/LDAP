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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;

/**
 * Decides which write a request means.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteRequestRouter
{
    public function __construct(
        private WritableLdapBackendInterface $backend,
        private WriteOperationDispatcher $dispatcher,
        private WriteCommandFactory $commandFactory = new WriteCommandFactory(),
    ) {}

    /**
     * @param callable(Dn): void $authorize Throws OperationException to deny removal of a subtree entry.
     * @throws OperationException
     */
    public function route(
        RequestInterface $request,
        WriteContext $context,
        callable $authorize,
    ): void {
        if ($this->isSubtreeDelete($request, $context)) {
            $this->backend->deleteSubtree(
                new DeleteCommand($request->getDn()),
                $context,
                $authorize,
            );

            return;
        }

        $this->dispatcher->dispatch(
            $this->commandFactory->fromRequest($request),
            $context,
        );
    }

    /**
     * @phpstan-assert-if-true DeleteRequest $request
     */
    private function isSubtreeDelete(
        RequestInterface $request,
        WriteContext $context,
    ): bool {
        return $request instanceof DeleteRequest
            && $context->getControls()->has(Control::OID_SUBTREE_DELETE);
    }
}
