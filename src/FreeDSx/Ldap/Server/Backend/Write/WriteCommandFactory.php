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
use FreeDSx\Ldap\Schema\Text;
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
            $request instanceof ModifyDnRequest => $this->moveCommand($request),
            default => throw new OperationException(
                'The requested operation is not supported.',
                ResultCode::NO_SUCH_OPERATION,
            ),
        };
    }

    /**
     * An unescaped comma parses without complaint and then reads as an RDN separator, which would land the entry
     * under a name the client never asked for.
     *
     * @throws OperationException
     */
    private function moveCommand(ModifyDnRequest $request): MoveCommand
    {
        if ($request->getNewRdn()->hasUnescapedComma()) {
            throw new OperationException(
                'The new RDN contains an unescaped comma.',
                ResultCode::INVALID_DN_SYNTAX,
            );
        }

        // A RelativeLDAPDN is an LDAPString, so bytes that do not spell one cannot name an entry.
        if (!Text::isUtf8($request->getNewRdn()->toString())) {
            throw new OperationException(
                'The new RDN is not encoded as UTF-8.',
                ResultCode::INVALID_DN_SYNTAX,
            );
        }

        return new MoveCommand(
            $request->getDn(),
            $request->getNewRdn(),
            $request->getDeleteOldRdn(),
            $request->getNewParentDn(),
        );
    }
}
