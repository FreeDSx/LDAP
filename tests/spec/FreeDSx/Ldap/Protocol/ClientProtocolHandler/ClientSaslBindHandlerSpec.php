<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSaslBindHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapper\SaslMessageWrapper;
use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientSaslBindHandlerSpec extends ObjectBehavior
{
    /**
     * @var LdapMessageResponse
     */
    protected $saslChallenge;

    /**
     * @var LdapMessageResponse
     */
    protected $saslComplete;

    function let(Sasl $sasl, ClientProtocolContext $context, ClientQueue $queue, ClientProtocolHandler $protocolHandler)
    {
        $queue->sendMessage(Argument::any())->willReturn($queue);
        $context->getControls()->willReturn([]);
        $context->getQueue()->willReturn($queue);
        $context->getRootDse()->willReturn(Entry::fromArray('', [
            'supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5'],
        ]));
        $queue->generateId()->willReturn(2, 3, 4, 5, 6);

        $this->saslChallenge = new LdapMessageResponse(
            1,
            new BindResponse(new LdapResult(ResultCode::SASL_BIND_IN_PROGRESS))
        );
        $this->saslComplete = new LdapMessageResponse(
            2,
            new BindResponse(new LdapResult(ResultCode::SUCCESS), 'foo')
        );

        $this->beConstructedWith($sasl);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientSaslBindHandler::class);
    }

    function it_should_implement_RequestHandlerInterface()
    {
        $this->shouldBeAnInstanceOf(RequestHandlerInterface::class);
    }

    function it_should_handle_a_sasl_bind_request(ChallengeInterface $challenge, MechanismInterface $mech, Sasl $sasl, ClientProtocolContext $context, ClientQueue $queue)
    {
        $saslBind = Operations::bindSasl(['username' => 'foo', 'password' => 'bar']);
        $context->getRequest()->willReturn($saslBind);
        $context->messageToSend()->willReturn(new LdapMessageRequest(1, $saslBind));


        $queue->getMessage(1)->willReturn($this->saslChallenge);
        $queue->getMessage(2)->willReturn($this->saslComplete);

        $sasl->select(['DIGEST-MD5', 'CRAM-MD5'], ['username' => 'foo', 'password' => 'bar'])
            ->shouldBeCalled()
            ->willReturn($mech);
        $mech->getName()->willReturn('DIGEST-MD5');
        $mech->challenge()->willReturn($challenge);

        $challenge->challenge(null, ["username" => "foo", "password" => "bar"])->willReturn(
            (new SaslContext())->setResponse('foo')
        );
        $challenge->challenge(Argument::type('string'), ["username" => "foo", "password" => "bar"])->willReturn(
            (new SaslContext())->setResponse('foo')->setIsComplete(true)
        );

        $context->getRootDse(true)->willReturn(
            Entry::fromArray('', [
                'supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5'],
            ])
        );

        $this->handleRequest($context)->shouldBeEqualTo($this->saslComplete);
    }

    function it_should_detect_a_downgrade_attack(ChallengeInterface $challenge, MechanismInterface $mech, Sasl $sasl, ClientProtocolContext $context, ClientQueue $queue)
    {
        $saslBind = Operations::bindSasl(['username' => 'foo', 'password' => 'bar']);
        $context->getRequest()->willReturn($saslBind);
        $context->messageToSend()->willReturn(new LdapMessageRequest(1, $saslBind));


        $queue->getMessage(1)->willReturn($this->saslChallenge);
        $queue->getMessage(2)->willReturn($this->saslComplete);

        $sasl->select(['PLAIN'], ['username' => 'foo', 'password' => 'bar'])
            ->shouldBeCalled()
            ->willReturn($mech);
        $mech->getName()->willReturn('PLAIN');
        $mech->challenge()->willReturn($challenge);

        $challenge->challenge(null, ["username" => "foo", "password" => "bar"])->willReturn(
            (new SaslContext())->setResponse('foo')
        );
        $challenge->challenge(Argument::type('string'), ["username" => "foo", "password" => "bar"])->willReturn(
            (new SaslContext())->setResponse('foo')->setIsComplete(true)
        );

        $context->getRootDse()->willReturn(
            Entry::fromArray('', [
                'supportedSaslMechanisms' => ['PLAIN'],
            ])
        );
        $context->getRootDse(true)->willReturn(
            Entry::fromArray('', [
                'supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5'],
            ])
        );

        $this->shouldThrow(new BindException('Possible SASL downgrade attack detected. The advertised SASL mechanisms have changed.'))
            ->during('handleRequest', [$context]);
    }

    function it_should_not_query_the_rootdse_if_the_mechanism_was_explicitly_specified(ChallengeInterface $challenge, MechanismInterface $mech, Sasl $sasl, ClientProtocolContext $context, ClientQueue $queue)
    {
        $saslBind = Operations::bindSasl(['username' => 'foo', 'password' => 'bar'], 'DIGEST-MD5');
        $context->getRequest()->willReturn($saslBind);
        $context->messageToSend()->willReturn(new LdapMessageRequest(1, $saslBind));

        $queue->getMessage(1)->willReturn($this->saslChallenge);
        $queue->getMessage(2)->willReturn($this->saslComplete);

        $sasl->get('DIGEST-MD5')
            ->shouldBeCalled()
            ->willReturn($mech);
        $mech->getName()->willReturn('DIGEST-MD5');
        $mech->challenge()->willReturn($challenge);

        $challenge->challenge(null, ["username" => "foo", "password" => "bar"])->willReturn(
            (new SaslContext())->setResponse('foo')
        );
        $challenge->challenge(Argument::type('string'), ["username" => "foo", "password" => "bar"])->willReturn(
            (new SaslContext())->setResponse('foo')->setIsComplete(true)
        );

        $context->getRootDse(Argument::any())->shouldNotBeCalled();
        $this->handleRequest($context)->shouldBeEqualTo($this->saslComplete);
    }

    function it_should_set_the_set_the_security_layer_on_the_queue_if_one_was_negotiated(SecurityLayerInterface $securityLayer, ChallengeInterface $challenge, MechanismInterface $mech, Sasl $sasl, ClientProtocolContext $context, ClientQueue $queue)
    {
        $saslBind = Operations::bindSasl(['username' => 'foo', 'password' => 'bar'], 'DIGEST-MD5');
        $context->getRequest()->willReturn($saslBind);
        $context->messageToSend()->willReturn(new LdapMessageRequest(1, $saslBind));

        $queue->getMessage(1)->willReturn($this->saslChallenge);
        $queue->getMessage(2)->willReturn($this->saslComplete);

        $sasl->get('DIGEST-MD5')
            ->shouldBeCalled()
            ->willReturn($mech);
        $mech->getName()->willReturn('DIGEST-MD5');
        $mech->challenge()->willReturn($challenge);

        $challenge->challenge(null, ["username" => "foo", "password" => "bar"])->willReturn(
            (new SaslContext())->setResponse('foo')
        );
        $challenge->challenge(Argument::type('string'), ["username" => "foo", "password" => "bar"])->willReturn(
            (new SaslContext())->setResponse('foo')
                ->setHasSecurityLayer(true)
                ->setIsAuthenticated(true)
                ->setIsComplete(true)
        );
        $mech->securityLayer()->shouldBeCalled()->willReturn($securityLayer);

        $queue->setMessageWrapper(Argument::type(SaslMessageWrapper::class))->shouldBeCalled();
        $this->handleRequest($context)->shouldBeEqualTo($this->saslComplete);
    }
}
