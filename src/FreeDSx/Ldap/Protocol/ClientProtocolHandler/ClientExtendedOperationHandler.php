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

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Response\TypedExtendedResponseDecoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\Exception\ConnectionException;

/**
 * Logic for handling extended operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientExtendedOperationHandler extends ClientBasicHandler
{
    public function __construct(
        ClientQueue $queue,
        private readonly TypedExtendedResponseDecoder $extendedResponses,
        private readonly DecodeContextFactory $contexts,
    ) {
        parent::__construct($queue);
    }

    /**
     * Decodes the extended response into its typed form when the request it answers has one.
     *
     * @throws OperationException
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function handleResponse(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom,
    ): ?LdapMessageResponse {
        /** @var ExtendedRequest $request */
        $request = $messageTo->getRequest();

        if (!$this->extendedResponses->has($request->getName())) {
            return parent::handleResponse(
                $messageTo,
                $messageFrom,
            );
        }

        return parent::handleResponse(
            $messageTo,
            $this->typedResponse(
                $messageFrom,
                $request->getName(),
            ),
        );
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     * @throws RuntimeException
     */
    public function handleRequest(LdapMessageRequest $message): ?LdapMessageResponse
    {
        $messageFrom = parent::handleRequest($message);

        /** @var ExtendedRequest $request */
        $request = $message->getRequest();
        if (!$this->extendedResponses->has($request->getName())) {
            return $messageFrom;
        }
        if ($messageFrom === null) {
            throw new OperationException('Expected an LDAP message response, but none was received.');
        }

        return $this->typedResponse(
            $messageFrom,
            $request->getName(),
        );
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    private function typedResponse(
        LdapMessageResponse $message,
        string $requestOid,
    ): LdapMessageResponse {
        $response = $message->getResponse();
        if (!$response instanceof ExtendedResponse) {
            throw new ProtocolException('Expected an extended response to the extended request.');
        }

        return new LdapMessageResponse(
            $message->getMessageId(),
            $this->extendedResponses->decode(
                $response,
                $requestOid,
                $this->contexts->create(),
            ),
            ...$message->controls()->toArray(),
        );
    }
}
