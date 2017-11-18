<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\Asn1\Encoder\EncoderInterface;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ExtendedResponseFactory;
use FreeDSx\Ldap\Tcp\ClientMessageQueue;
use FreeDSx\Ldap\Tcp\Socket;
use FreeDSx\Ldap\Tcp\SocketPool;

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
     * @var SocketPool
     */
    protected $pool;

    /**
     * @var Socket
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
     * @param ClientMessageQueue|null $queue
     * @param SocketPool|null $pool
     */
    public function __construct(array $options, ClientMessageQueue $queue = null, SocketPool $pool = null)
    {
        $this->options = $options;
        $this->encoder = new BerEncoder();
        $this->pool = $pool ?: new SocketPool($options);
        $this->queue = $queue;
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
     * @return null|Socket
     */
    public function getSocket() : ?Socket
    {
        return $this->tcp;
    }

    /**
     * @param RequestInterface $request
     * @param Control[] $controls
     * @return LdapMessageResponse|null
     * @throws ConnectionException
     * @throws UnsolicitedNotificationException
     */
    public function send(RequestInterface $request, Control ...$controls) : ?LdapMessageResponse
    {
        $messageTo = new LdapMessageRequest(
            ++$this->messageId,
            $request,
            ...array_merge($this->controls->toArray(), $controls)
        );

        try {
            $messageFrom = $this->handleRequest($messageTo);
        } catch (UnsolicitedNotificationException $exception) {
            if ($exception->getOid() === ExtendedResponse::OID_NOTICE_OF_DISCONNECTION) {
                $this->closeTcp();
                throw new ConnectionException(
                    sprintf('The remote server has disconnected the session. %s', $exception->getMessage()),
                    $exception->getCode()
                );
            }

            throw $exception;
        }

        if ($messageFrom) {
            $this->handleResponse($messageTo, $messageFrom);
        }

        return $messageFrom;
    }

    /**
     * @param LdapMessageRequest $messageTo
     * @param LdapMessageResponse $messageFrom
     * @throws BindException
     * @throws OperationException
     */
    protected function handleResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom) : void
    {
        if ($messageFrom->getResponse() instanceof ExtendedResponse) {
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

        throw new OperationException($result->getDiagnosticMessage(), $result->getResultCode());
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
            $messageFrom = $this->queue()->getMessage($messageTo->getMessageId());
        }

        return $messageFrom;
    }

    /**
     * @param LdapMessageRequest $messageTo
     * @param LdapMessageResponse $messageFrom
     */
    protected function handleExtendedResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom) : void
    {
        if (!$messageTo->getRequest() instanceof ExtendedRequest) {
            return;
        }

        /** @var ExtendedRequest $request */
        $request = $messageTo->getRequest();
        if (!ExtendedResponseFactory::has($request->getName())) {
            return;
        }

        //@todo Should not have to do this. But the extended response name OID from the request is needed to complete.
        $response = ExtendedResponseFactory::get($messageFrom->getResponse()->toAsn1(), $request->getName());
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
        $messageFrom = $this->queue()->getMessage($messageTo->getMessageId());

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
            foreach ($this->queue()->getMessages($messageTo->getMessageId()) as $message) {
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
            new SearchResponse($done->getResponse(), new Entries(...$entries)),
            ...$done->controls()->toArray()
        );
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
     * @return Socket
     */
    protected function tcp() : Socket
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
            $this->queue = new ClientMessageQueue($this->tcp());
        }

        return $this->queue;
    }
}
