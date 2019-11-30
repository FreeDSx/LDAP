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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapper\SaslMessageWrapper;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Sasl\SaslContext;

/**
 * Logic for handling a SASL bind.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientSaslBindHandler implements RequestHandlerInterface
{
    /**
     * @var ControlBag
     */
    protected $controls;

    /**
     * @{@inheritDoc}
     */
    public function handleRequest(LdapMessageRequest $message, ClientQueue $queue, array $options): ?LdapMessageResponse
    {
        $this->controls = $message->controls();
        $queue->sendMessage($message);

        /** @var LdapMessageResponse $response */
        $response = $queue->getMessage($message->getMessageId());
        $saslResponse = $response->getResponse();
        if (!$saslResponse instanceof BindResponse) {
            throw new ProtocolException(sprintf(
                'Expected a bind response during a SASL bind. But got: %s',
                get_class($saslResponse)
            ));
        }
        if ($saslResponse->getResultCode() !== ResultCode::SASL_BIND_IN_PROGRESS) {
            return $response;
        }
        $response = $this->processSaslChallenge($message, $queue, $saslResponse);

        return $response;
    }

    protected function processSaslChallenge(
        LdapMessageRequest $message,
        ClientQueue $queue,
        BindResponse $saslResponse
    ): ?LdapMessageResponse {
        /** @var SaslBindRequest $request */
        $request = $message->getRequest();
        $mech = (new Sasl())->get($request->getMechanism());
        $challenge = $mech->challenge();
        $response = null;

        do {
            $context = $challenge->challenge($saslResponse->getSaslCredentials(), $request->getOptions());
            $saslBind = Operations::bindSasl($request->getMechanism(), [], $context->getResponse());
            $response = $this->sendRequestGetResponse($saslBind, $queue);
            $saslResponse = $response->getResponse();
            if (!$saslResponse instanceof BindResponse) {
                throw new BindException(sprintf(
                    'Expected a bind response during a SASL bind. But got: %s',
                    get_class($saslResponse)
                ));
            }
        } while (!$this->isChallengeComplete($context, $saslResponse));

        if (!$context->isComplete()) {
            $context = $challenge->challenge($saslResponse->getSaslCredentials(), $request->getOptions());
        }

        if ($saslResponse->getResultCode() === ResultCode::SUCCESS && $context->hasSecurityLayer()) {
            $queue->setMessageWrapper(new SaslMessageWrapper($mech->security(), $context));
        }

        return $response;
    }

    protected function sendRequestGetResponse(SaslBindRequest $request, ClientQueue $queue): LdapMessageResponse
    {
        $messageTo = new LdapMessageRequest(
            $queue->generateId(),
            $request,
            ...$this->controls
        );
        $queue->sendMessage($messageTo);

        /** @var LdapMessageResponse $messageFrom */
        $messageFrom = $queue->getMessage($messageTo->getMessageId());

        return $messageFrom;
    }

    protected function isChallengeComplete(SaslContext $context, BindResponse $response): bool
    {
        if ($context->isComplete() || $context->getResponse() === null) {
            return true;
        }

        if ($response->getResultCode() === ResultCode::SUCCESS) {
            return true;
        }

        return $response->getResultCode() !== ResultCode::SASL_BIND_IN_PROGRESS;
    }
}
