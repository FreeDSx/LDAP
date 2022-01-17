<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\Exception\ConnectionException;
use function in_array;

/**
 * Logic for handling basic operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientBasicHandler implements RequestHandlerInterface, ResponseHandlerInterface
{
    /**
     * RFC 4511, A.1. These are considered result codes that do not indicate an error condition.
     */
    protected const NON_ERROR_CODES = [
        ResultCode::SUCCESS,
        ResultCode::COMPARE_FALSE,
        ResultCode::COMPARE_TRUE,
        ResultCode::REFERRAL,
        ResultCode::SASL_BIND_IN_PROGRESS,
    ];

    /**
     * @param ClientProtocolContext $context
     * @return LdapMessageResponse
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     * @throws EncoderException
     */
    public function handleRequest(ClientProtocolContext $context): ?LdapMessageResponse
    {
        $queue = $context->getQueue();
        $message = $context->messageToSend();
        $queue->sendMessage($message);

        return $queue->getMessage($message->getMessageId());
    }

    /**
     * @param LdapMessageRequest $messageTo
     * @param LdapMessageResponse $messageFrom
     * @param ClientQueue $queue
     * @param array $options
     * @return LdapMessageResponse
     * @throws BindException
     * @throws OperationException
     */
    public function handleResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom, ClientQueue $queue, array $options): ?LdapMessageResponse
    {
        $result = $messageFrom->getResponse();

        # No action to take if we received something that isn't an LDAP Result, or on success.
        if (!$result instanceof LdapResult || $result->getResultCode() === ResultCode::SUCCESS) {
            return $messageFrom;
        }

        # The success code above should satisfy the majority of cases. This checks if the result code is really a non
        # error condition defined in RFC 4511, A.1
        if (in_array($result->getResultCode(), self::NON_ERROR_CODES, true)) {
            return $messageFrom;
        }

        if ($messageTo->getRequest() instanceof BindRequest) {
            throw new BindException(
                sprintf('Unable to bind to LDAP. %s', $result->getDiagnosticMessage()),
                $result->getResultCode()
            );
        }

        throw new OperationException($result->getDiagnosticMessage(), $result->getResultCode());
    }
}
