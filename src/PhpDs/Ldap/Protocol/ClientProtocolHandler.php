<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Protocol;

use PhpDs\Ldap\Asn1\Encoder\BerEncoder;
use PhpDs\Ldap\Asn1\Encoder\EncoderInterface;
use PhpDs\Ldap\Control\Control;
use PhpDs\Ldap\Control\ControlBag;
use PhpDs\Ldap\Exception\BindException;
use PhpDs\Ldap\Exception\ConnectionException;
use PhpDs\Ldap\Exception\ProtocolException;
use PhpDs\Ldap\Operation\LdapResult;
use PhpDs\Ldap\Operation\Request\BindRequest;
use PhpDs\Ldap\Operation\Request\ExtendedRequest;
use PhpDs\Ldap\Operation\Request\RequestInterface;
use PhpDs\Ldap\Operation\Request\SearchRequest;
use PhpDs\Ldap\Operation\Request\UnbindRequest;
use PhpDs\Ldap\Operation\Response\ExtendedResponse;
use PhpDs\Ldap\Operation\Response\SearchResponse;
use PhpDs\Ldap\Operation\Response\SearchResultDone;
use PhpDs\Ldap\Operation\Response\SearchResultEntry;
use PhpDs\Ldap\Operation\ResultCode;
use PhpDs\Ldap\Protocol\Factory\ExtendedResponseFactory;
use PhpDs\Ldap\Tcp\ClientMessageQueue;
use PhpDs\Ldap\Tcp\TcpPool;
use PhpDs\Ldap\Tcp\TcpClient;

/**
 * Handles client specific protocol communication details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandler
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
     * @var TcpPool
     */
    protected $pool;

    /**
     * @var TcpClient
     */
    protected $tcp;

    /**
     * @var ClientMessageQueue
     */
    protected $queue;

    /**
     * @var EncoderInterface
     */
    protected $encoder;

    /**
     * @var array
     */
    protected $options;

    /**
     * @var ControlBag
     */
    protected $controls;

    /**
     * @var int
     */
    protected $messageId = 0;

    /**
     * @param array $options
     * @param EncoderInterface|null $encoder
     * @param TcpPool|null $pool
     */
    public function __construct(array $options, EncoderInterface $encoder = null, TcpPool $pool = null)
    {
        $this->options = $options;
        $this->encoder = new BerEncoder();
        $this->pool = new TcpPool($options);
        $this->controls = new ControlBag();
    }

    /**
     * @return ControlBag
     */
    public function controls() : ControlBag
    {
        return $this->controls;
    }

    /**
     * @return null|TcpClient
     */
    public function getTcpClient() : ?TcpClient
    {
        return $this->tcp;
    }

    /**
     * @param RequestInterface $request
     * @param Control[] $controls
     * @return null|LdapMessageResponse
     */
    public function send(RequestInterface $request, Control ...$controls) : ?LdapMessageResponse
    {
        $messageTo = new LdapMessageRequest(
            ++$this->messageId,
            $request,
            ...array_merge($this->controls->toArray(), $controls)
        );
        $messageFrom = $this->handleRequest($messageTo);

        if ($messageFrom) {
            $this->handleResponse($messageTo, $messageFrom);
        }

        return $messageFrom;
    }

    /**
     * @param LdapMessageRequest $messageTo
     * @param LdapMessageResponse $messageFrom
     * @throws BindException
     * @throws ProtocolException
     */
    protected function handleResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom) : void
    {
        if ($this->isUnsolicited($messageFrom)) {
            $this->handleUnsolicitedNotification($messageFrom);
        } elseif ($messageFrom->getResponse() instanceof ExtendedResponse) {
            $this->handleExtendedResponse($messageTo, $messageFrom);
        }
        $result = $messageFrom->getResponse();

        # No action to take if there was no result, we received something that isn't an LDAP Result, or on success.
        if ($result === null || !$result instanceof LdapResult || $result->getResultCode() === ResultCode::SUCCESS) {
            return;
        }

        # The success code above should satisfy the majority of cases. This checks if the result code is really a non
        # error condition defined in RFC 4511, A.1
        if (in_array($result->getResultCode(), self::NON_ERROR_CODES)) {
            return;
        }

        if ($messageTo->getRequest() instanceof BindRequest) {
            throw new BindException(
                sprintf('Unable to bind to LDAP. %s', $result->getDiagnosticMessage()),
                $result->getResultCode()
            );
        }

        $this->throwProtocolException($result);
    }

    /**
     * @param LdapMessageRequest $messageTo
     * @return null|LdapMessageResponse
     */
    protected function handleRequest(LdapMessageRequest $messageTo) : ?LdapMessageResponse
    {
        $request = $messageTo->getRequest();
        if ($request instanceof SearchRequest && $request->getBaseDn() === null) {
            $request->setBaseDn($this->options['base_dn'] ?? null);
        }
        $this->tcp()->write($this->encoder->encode($messageTo->toAsn1()));

        $messageFrom = null;
        if ($request instanceof UnbindRequest) {
            # An unbind is like a 'quit' statement. It expects no PDU in return.
            $this->closeTcp();
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS) {
            $this->handleStartTls($messageTo);
        } elseif ($request instanceof SearchRequest) {
            $messageFrom = $this->handleSearchResponse($messageTo);
        } else {
            $messageFrom = $this->queue()->getMessage();
        }

        return $messageFrom;
    }

    /**
     * Check for an unsolicited notification message. It is defined as being a message with an ID of zero and a response
     * of the ExtendedResponse type.
     *
     * @param null|LdapMessageResponse $message
     * @return bool
     */
    protected function isUnsolicited(?LdapMessageResponse $message)
    {
        return $message->getMessageId() === 0 && $message->getResponse() instanceof ExtendedResponse;
    }

    /**
     * @param LdapMessageResponse $message
     * @throws ConnectionException
     */
    protected function handleUnsolicitedNotification(LdapMessageResponse $message) : void
    {
        /** @var ExtendedResponse $response */
        $response = $message->getResponse();
        if ($response->getName() === ExtendedResponse::OID_NOTICE_OF_DISCONNECTION) {
            $this->closeTcp();
            throw new ConnectionException(
                sprintf('The remove server has disconnected the session. %s', $response->getDiagnosticMessage()),
                $response->getResultCode()
            );
        }

        $this->throwProtocolException($response);
    }

    /**
     * @param LdapMessageRequest $messageTo
     * @param LdapMessageResponse $messageFrom
     */
    protected function handleExtendedResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom) : void
    {
        if ($messageTo->getMessageId() !== $messageFrom->getMessageId() || !$messageTo->getRequest() instanceof ExtendedRequest) {
            return;
        }

        /** @var ExtendedRequest $request */
        $request = $messageTo->getRequest();
        if (!ExtendedResponseFactory::has($request->getName())) {
            return;
        }

        //@todo Should not have to do this. But the extended response name OID from the request is needed to complete.
        $response = ExtendedResponseFactory::get($messageTo->getRequest()->toAsn1(), $request->getName());
        $prop = (new \ReflectionClass(LdapMessageResponse::class))->getProperty('response');
        $prop->setAccessible(true);
        $prop->setValue($messageFrom, $response);
    }

    /**
     * @param LdapMessageRequest $messageTo
     * @throws ConnectionException
     */
    protected function handleStartTls(LdapMessageRequest $messageTo) : void
    {
        $messageFrom = null;

        /** @var LdapMessageResponse $message */
        foreach ($this->queue()->getMessages() as $message) {
            if ($message->getMessageId() === $messageTo->getMessageId()) {
                $messageFrom = $message;
            }
        }

        if ($messageFrom->getResponse()->getResultCode() !== ResultCode::SUCCESS) {
            throw new ConnectionException(sprintf(
                'Unable to start TLS: %s',
                $messageFrom->getResponse()->getDiagnosticMessage()
            ));
        }

        $this->tcp()->encrypt(true);
    }

    /**
     * @param LdapMessage $messageTo
     * @return LdapMessageResponse
     */
    protected function handleSearchResponse(LdapMessage $messageTo) : LdapMessageResponse
    {
        $entries = [];
        $done = null;

        while ($done === null) {
            /** @var LdapMessageResponse $message */
            foreach ($this->queue()->getMessages() as $message) {
                if ($this->isUnsolicited($message)) {
                    $this->handleUnsolicitedNotification($message);
                }
                // @todo This should not be ignored...
                if ($message->getMessageId() !== $messageTo->getMessageId()) {
                    continue;
                }
                $response = $message->getResponse();
                if ($response instanceof SearchResultEntry) {
                    $entries[] = $response->getEntry();
                } elseif ($response instanceof SearchResultDone) {
                    $done = $message;
                }
            }
        }

        /** @var LdapMessageResponse $done */
        return new LdapMessageResponse(
            $done->getMessageId(),
            new SearchResponse($done->getResponse(), ...$entries),
            ...$done->controls()->toArray()
        );
    }

    /**
     * @param LdapResult $result
     * @throws ProtocolException
     */
    protected function throwProtocolException(LdapResult $result)
    {
        throw new ProtocolException($result->getDiagnosticMessage(), $result->getResultCode());
    }

    /**
     * Closes the TCP connection and resets the message ID back to 0.
     */
    protected function closeTcp() : void
    {
        $this->tcp->close();
        $this->messageId = 0;
        $this->tcp = null;
    }

    /**
     * @return TcpClient
     */
    protected function tcp() : TcpClient
    {
        if ($this->tcp === null) {
            $this->tcp = $this->pool->connect();
        }

        return $this->tcp;
    }

    /**
     * @return ClientMessageQueue
     */
    protected function queue() : ClientMessageQueue
    {
        if ($this->queue === null) {
            $this->queue = new ClientMessageQueue($this->tcp(), $this->encoder);
        }

        return $this->queue;
    }
}
