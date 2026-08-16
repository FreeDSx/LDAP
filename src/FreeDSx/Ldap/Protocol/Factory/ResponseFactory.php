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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;

/**
 * For a specific request and result code/diagnostic, get the response object if possible.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ResponseFactory
{
    /**
     * Retrieve the expected response type for the request that was given.
     *
     * @param Dn|null $matchedDn Matched ancestor; emitted as matchedDN when non-null.
     * @param Control ...$controls Response controls to attach to the resulting message.
     */
    public function getStandardResponse(
        LdapMessageRequest $message,
        int $resultCode = ResultCode::SUCCESS,
        string $diagnostic = '',
        ?Dn $matchedDn = null,
        Control ...$controls,
    ): LdapMessageResponse {
        $request = $message->getRequest();
        $dn = $matchedDn?->toString() ?? '';

        $response = match (true) {
            $request instanceof BindRequest => new BindResponse(
                new LdapResult(
                    $resultCode,
                    $dn,
                    $diagnostic,
                ),
            ),
            $request instanceof SearchRequest => new SearchResultDone(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof AddRequest => new AddResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof CompareRequest => new CompareResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof DeleteRequest => new DeleteResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof ModifyDnRequest => new ModifyDnResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof ModifyRequest => new ModifyResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof ExtendedRequest => new ExtendedResponse(
                new LdapResult(
                    $resultCode,
                    $dn,
                    $diagnostic,
                ),
                $request->getName(),
            ),
            default => null,
        };

        if ($response === null) {
            return $this->getExtendedError(
                'Invalid request.',
                ResultCode::OPERATIONS_ERROR,
            );
        }

        return new LdapMessageResponse(
            $message->getMessageId(),
            $response,
            ...$controls,
        );
    }

    /**
     * The response owed to a message whose contents could not be decoded, keyed by its protocolOp tag.
     *
     * The request object never existed, so the tag alone has to pick the response type the client is waiting on.
     */
    public function getDecodeFailureResponse(
        int $messageId,
        int $protocolOpTag,
        string $diagnostic,
        int $resultCode = ResultCode::PROTOCOL_ERROR,
    ): ?LdapMessageResponse {
        $response = match ($protocolOpTag) {
            0 => new BindResponse(new LdapResult(
                $resultCode,
                diagnosticMessage: $diagnostic,
            )),
            3 => new SearchResultDone(
                $resultCode,
                diagnosticMessage: $diagnostic,
            ),
            6 => new ModifyResponse(
                $resultCode,
                diagnosticMessage: $diagnostic,
            ),
            8 => new AddResponse(
                $resultCode,
                diagnosticMessage: $diagnostic,
            ),
            10 => new DeleteResponse(
                $resultCode,
                diagnosticMessage: $diagnostic,
            ),
            12 => new ModifyDnResponse(
                $resultCode,
                diagnosticMessage: $diagnostic,
            ),
            14 => new CompareResponse(
                $resultCode,
                diagnosticMessage: $diagnostic,
            ),
            23 => new ExtendedResponse(new LdapResult(
                $resultCode,
                diagnosticMessage: $diagnostic,
            )),
            // Unbind and Abandon have no response, and a response tag is not a request at all.
            default => null,
        };

        return $response === null
            ? null
            : new LdapMessageResponse(
                $messageId,
                $response,
            );
    }

    /**
     * Retrieve an extended error, which has a message ID of zero.
     *
     * @param Control ...$controls Response controls to attach to the resulting message.
     */
    public function getExtendedError(
        string $message,
        int $errorCode,
        ?string $responseName = null,
        Control ...$controls,
    ): LdapMessageResponse {
        return new LdapMessageResponse(
            0,
            new ExtendedResponse(
                new LdapResult(
                    $errorCode,
                    '',
                    $message,
                ),
                $responseName,
            ),
            ...$controls,
        );
    }
}
