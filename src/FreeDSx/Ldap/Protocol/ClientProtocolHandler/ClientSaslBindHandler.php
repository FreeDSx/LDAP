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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\DigestMD5Options;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\SaslInterface;

/**
 * Logic for handling a SASL bind.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientSaslBindHandler implements RequestHandlerInterface
{
    use MessageCreationTrait;

    /**
     * @var Control[]
     */
    private array $controls = [];

    public function __construct(
        private readonly ClientQueue $queue,
        private readonly RootDseLoader $rootDseLoader,
        private readonly SaslInterface $sasl = new Sasl(),
    ) {}

    /**
     * {@@inheritDoc}
     *
     * @throws BindException
     * @throws OperationException
     * @throws SaslException
     */
    public function handleRequest(LdapMessageRequest $message): ?LdapMessageResponse
    {
        /** @var SaslBindRequest $request */
        $request = $message->getRequest();
        $this->refuseSecurityLayer($request);
        $this->controls = $message->controls()->toArray();

        # If we are selecting a mechanism from the RootDSE, we must check for a downgrade afterwards.
        $detectDowngrade = ($request->getMechanism() === '');
        $mech = $this->selectSaslMech($request);

        # Compute the client's initial response. Client-first mechanisms (PLAIN, SCRAM, EXTERNAL)
        # produce one to carry in the initial bind; server-first mechanisms produce null.
        $challenge = $mech->challenge();
        $context = $challenge->challenge(
            null,
            $request->getOptions(),
        );

        $response = $this->sendInitialBind(
            $request,
            $context,
        );
        $saslResponse = $response->getResponse();
        if (!$saslResponse instanceof BindResponse) {
            throw new ProtocolException(sprintf(
                'Expected a bind response during a SASL bind. But got: %s',
                get_class($saslResponse),
            ));
        }

        if ($saslResponse->getResultCode() === ResultCode::SASL_BIND_IN_PROGRESS) {
            $response = $this->processSaslChallenge(
                $request,
                $this->queue,
                $saslResponse,
                $challenge,
            );
        }

        if (
            $detectDowngrade
            && $response->getResponse() instanceof BindResponse
            && $response->getResponse()->getResultCode() === ResultCode::SUCCESS
        ) {
            $this->checkDowngradeAttempt();
        }

        return $response;
    }

    /**
     * Sends the initial bind carrying the client's first response, then returns the server's reply.
     */
    private function sendInitialBind(
        SaslBindRequest $request,
        SaslContext $context,
    ): LdapMessageResponse {
        $message = $this->makeRequest(
            $this->queue,
            Operations::bindSasl(
                $request->getOptions(),
                MechanismName::from($request->getMechanism()),
                $context->getResponse(),
            )->setVersion($request->getVersion()),
            $this->controls,
        );
        $this->queue->sendMessage($message);

        return $this->queue->getMessage($message->getMessageId());
    }

    /**
     * @throws SaslException
     */
    private function selectSaslMech(
        SaslBindRequest $request,
    ): MechanismInterface {
        if ($request->getMechanism() !== '') {
            $mech = $this->sasl->get(MechanismName::from($request->getMechanism()));
            $request->setMechanism($mech->getName()->value);

            return $mech;
        }
        $rootDse = $this->rootDseLoader->load();
        $choices = $this->parseKnownMechanisms($rootDse->get('supportedSaslMechanisms'));
        $mech = $this->sasl->select(
            $choices,
            $request->getSelectOptions(),
        );
        $request->setMechanism($mech->getName()->value);

        return $mech;
    }

    /**
     * @throws BindException
     * @throws SaslException
     */
    private function processSaslChallenge(
        SaslBindRequest $request,
        ClientQueue $queue,
        BindResponse $saslResponse,
        ChallengeInterface $challenge,
    ): LdapMessageResponse {
        do {
            $context = $challenge->challenge(
                $saslResponse->getSaslCredentials(),
                $request->getOptions(),
            );
            $saslBind = Operations::bindSasl(
                $request->getOptions(),
                MechanismName::from($request->getMechanism()),
                $context->getResponse(),
            );
            $response = $this->sendRequestGetResponse(
                $saslBind,
                $queue,
            );
            $saslResponse = $response->getResponse();
            if (!$saslResponse instanceof BindResponse) {
                throw new BindException(sprintf(
                    'Expected a bind response during a SASL bind. But got: %s',
                    get_class($saslResponse),
                ));
            }
        } while (!$this->isChallengeComplete($context, $saslResponse));

        if (!$context->isComplete()) {
            // The server's final message is still verified, such as the DIGEST-MD5 rspauth.
            $challenge->challenge(
                $saslResponse->getSaslCredentials(),
                $request->getOptions(),
            );
        }

        return $response;
    }

    /**
     * Refuses a DIGEST-MD5 bind that asks for an integrity or privacy layer, which is not supported.
     *
     * @throws BindException
     */
    private function refuseSecurityLayer(SaslBindRequest $request): void
    {
        $options = $request->getOptions();
        if (!$options instanceof DigestMD5Options) {
            return;
        }
        if ($options->isUseIntegrity() || $options->isUsePrivacy()) {
            throw new BindException('The SASL integrity and privacy layers are not supported. Use TLS instead.');
        }
    }

    private function sendRequestGetResponse(
        SaslBindRequest $request,
        ClientQueue $queue,
    ): LdapMessageResponse {
        $messageTo = $this->makeRequest($queue, $request, $this->controls);
        $queue->sendMessage($messageTo);

        return $queue->getMessage($messageTo->getMessageId());
    }

    private function isChallengeComplete(
        SaslContext $context,
        BindResponse $response,
    ): bool {
        if ($context->isComplete() || $context->getResponse() === null) {
            return true;
        }

        if ($response->getResultCode() === ResultCode::SUCCESS) {
            return true;
        }

        return $response->getResultCode() !== ResultCode::SASL_BIND_IN_PROGRESS;
    }

    /**
     * Converts server-advertised mechanism name strings into known MechanismName values, discarding unrecognised ones.
     *
     * @return MechanismName[]
     */
    private function parseKnownMechanisms(?Attribute $attribute): array
    {
        $known = [];
        foreach ($attribute?->getValues() ?? [] as $name) {
            $mech = MechanismName::tryFrom($name);
            if ($mech !== null) {
                $known[] = $mech;
            }
        }

        return $known;
    }

    /**
     * @throws BindException
     * @throws OperationException
     */
    private function checkDowngradeAttempt(): void
    {
        $priorRootDse = $this->rootDseLoader->load();
        $rootDse = $this->rootDseLoader->load(reload: true);

        $mechs = $rootDse->get('supportedSaslMechanisms');
        $priorMechs = $priorRootDse->get('supportedSaslMechanisms');
        $priorMechs = $priorMechs !== null ? $priorMechs->getValues() : [];
        $mechs = $mechs !== null ? $mechs->getValues() : [];

        if (count(array_diff($mechs, $priorMechs)) !== 0) {
            throw new BindException(
                'Possible SASL downgrade attack detected. The advertised SASL mechanisms have changed.',
            );
        }
    }
}
