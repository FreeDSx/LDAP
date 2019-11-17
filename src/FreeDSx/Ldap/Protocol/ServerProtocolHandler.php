<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerBindHandlerFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles server-client specific protocol interactions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerProtocolHandler
{
    /**
     * @var array
     */
    protected $options = [
        'allow_anonymous' => false,
        'require_authentication' => true,
        'request_handler' => null,
        'dse_alt_server' => null,
        'dse_naming_contexts' => 'dc=FreeDSx,dc=local',
        'dse_vendor_name' => 'FreeDSx',
        'dse_vendor_version' => null,
    ];

    /**
     * @var ServerQueue
     */
    protected $queue;

    /**
     * @var int[]
     */
    protected $messageIds = [];

    /**
     * @var RequestHandlerInterface
     */
    protected $dispatcher;

    /**
     * @var ServerAuthorization
     */
    protected $authorizer;

    /**
     * @var ServerProtocolHandlerFactory
     */
    protected $protocolHandlerFactory;

    /**
     * @var ResponseFactory
     */
    protected $responseFactory;

    /**
     * @var ServerBindHandlerFactory
     */
    protected $bindHandlerFactory;

    public function __construct(
        ServerQueue $queue,
        RequestHandlerInterface $dispatcher,
        array $options = [],
        ServerProtocolHandlerFactory $protocolHandlerFactory = null,
        ServerBindHandlerFactory $bindHandlerFactory = null,
        ServerAuthorization $authorizer = null,
        ResponseFactory $responseFactory = null
    ) {
        $this->queue = $queue;
        $this->dispatcher = $dispatcher;
        $this->options = \array_merge($this->options, $options);
        $this->authorizer = $authorizer ?? new ServerAuthorization(null, $this->options);
        $this->protocolHandlerFactory = $protocolHandlerFactory ?? new ServerProtocolHandlerFactory();
        $this->bindHandlerFactory = $bindHandlerFactory ?? new ServerBindHandlerFactory();
        $this->responseFactory = $responseFactory ?? new ResponseFactory();
    }

    /**
     * Listens for messages from the socket and handles the responses/actions needed.
     */
    public function handle(): void
    {
        try {
            while ($message = $this->queue->getMessage()) {
                $this->dispatchRequest($message);
                # If a protocol handler closed the TCP connection, then just break here...
                if (!$this->queue->isConnected()) {
                    break;
                }
            }
        } catch (OperationException $e) {
            # OperationExceptions may be thrown by any handler and will be sent back to the client as the response
            # specific error code and message associated with the exception.
            if (isset($message)) {
                $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                    $message,
                    $e->getCode(),
                    $e->getMessage()
                ));
            }
        } catch (EncoderException | ProtocolException $e) {
            # Per RFC 4511, 4.1.1 if the PDU cannot be parsed or is otherwise malformed a disconnect should be sent with a
            # result code of protocol error.
            $this->sendNoticeOfDisconnect('The message encoding is malformed.');
        } catch (\Exception | \Throwable $e) {
            if ($this->queue->isConnected()) {
                $this->sendNoticeOfDisconnect();
            }
        } finally {
            if ($this->queue->isConnected()) {
                $this->queue->close();
            }
        }
    }

    /**
     * Routes requests from the message queue based off the current authorization state and what protocol handler the
     * request is mapped to.
     *
     * @throws OperationException
     */
    protected function dispatchRequest(LdapMessageRequest $message): void
    {
        if (!$this->isValidRequest($message)) {
            return;
        }

        $this->messageIds[] = $message->getMessageId();

        # Send auth requests to the specific handler for it...
        if ($this->authorizer->isAuthenticationRequest($message->getRequest())) {
            $this->authorizer->setToken($this->handleAuthRequest($message));

            return;
        }
        $request = $message->getRequest();
        $handler = $this->protocolHandlerFactory->get($request);

        # They are authenticated or authentication is not required, so pass the request along...
        if ($this->authorizer->isAuthenticated() || !$this->authorizer->isAuthenticationRequired($request)) {
            $handler->handleRequest(
                $message,
                $this->authorizer->getToken(),
                $this->dispatcher,
                $this->queue,
                $this->options
            );
        # Authentication is required, but they have not authenticated...
        } else {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                'Authentication required.'
            ));
        }
    }

    /**
     * Checks that the message ID is valid. It cannot be zero or a message ID that was already used.
     */
    protected function isValidRequest(LdapMessageRequest $message): bool
    {
        if ($message->getMessageId() === 0) {
            $this->queue->sendMessage($this->responseFactory->getExtendedError(
                'The message ID 0 cannot be used in a client request.',
                ResultCode::PROTOCOL_ERROR
            ));

            return false;
        }
        if (\in_array($message->getMessageId(), $this->messageIds, true)) {
            $this->queue->sendMessage($this->responseFactory->getExtendedError(
                sprintf('The message ID %s is not valid.', $message->getMessageId()),
                ResultCode::PROTOCOL_ERROR
            ));

            return false;
        }

        return true;
    }

    /**
     * Sends a bind request to the bind handler and returns the token.
     *
     * @throws OperationException
     */
    protected function handleAuthRequest(LdapMessageRequest $message): TokenInterface
    {
        if (!$this->authorizer->isAuthenticationTypeSupported($message->getRequest())) {
            throw new OperationException(
                'The requested authentication type is not supported.',
                ResultCode::AUTH_METHOD_UNSUPPORTED
            );
        }

        return $this->bindHandlerFactory->get($message->getRequest())->handleBind(
            $message,
            $this->dispatcher,
            $this->queue,
            $this->options
        );
    }

    protected function sendNoticeOfDisconnect(string $message = ''): void
    {
        $this->queue->sendMessage($this->responseFactory->getExtendedError(
            $message,
            ResultCode::PROTOCOL_ERROR,
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
        ));
    }
}
