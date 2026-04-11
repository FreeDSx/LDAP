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
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;

/**
 * Translates LDAP protocol request objects into write command DTOs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WriteCommandFactory
{
    /**
     * @throws OperationException
     */
    public function fromRequest(RequestInterface $request): WriteRequestInterface
    {
        return match (true) {
            $request instanceof AddRequest => new AddCommand($request->getEntry()),
            $request instanceof DeleteRequest => new DeleteCommand($request->getDn()),
            $request instanceof ModifyRequest => new UpdateCommand(
                $request->getDn(),
                $request->getChanges(),
            ),
            $request instanceof ModifyDnRequest => new MoveCommand(
                $request->getDn(),
                $request->getNewRdn(),
                $request->getDeleteOldRdn(),
                $request->getNewParentDn(),
            ),
            default => throw new OperationException(
                'The requested operation is not supported.',
                ResultCode::NO_SUCH_OPERATION,
            ),
        };
    }
}
