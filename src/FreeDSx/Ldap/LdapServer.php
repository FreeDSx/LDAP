<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Socket\SocketServer;

/**
 * The LDAP server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapServer
{
    /**
     * @var array
     */
    protected $options = [
        'ip' => '0.0.0.0',
        'port' => 389,
        'idle_timeout' => 600,
        'require_authentication' => true,
        'allow_anonymous' => false,
        'request_handler' => null,
        'ssl_cert' => null,
        'ssl_cert_passphrase' => null,
        'dse_alt_server' => null,
        'dse_naming_contexts' => 'dc=FreeDSx,dc=local',
        'dse_vendor_name' => 'FreeDSx',
        'dse_vendor_version' => null,
    ];

    /**
     * @var ServerRunnerInterface
     */
    protected $runner;

    /**
     * @param array $options
     * @param ServerRunnerInterface|null $serverRunner
     */
    public function __construct(array $options = [], ServerRunnerInterface $serverRunner = null)
    {
        $this->options = array_merge($this->options, $options);
        $this->validateRequestHandler();
        $this->runner = $serverRunner ?? new PcntlServerRunner($this->options);
    }

    /**
     * Runs the LDAP server. Binds the socket on the request IP/port and sends it to the server runner.
     */
    public function run(): void
    {
        $this->runner->run(SocketServer::bind($this->options['ip'], $this->options['port'], $this->options));
    }

    /**
     * The request handler should be constructed from a string class name. This is to make sure that each client instance
     * has its own version of the handler to avoid conflicts and potential security issues sharing a request handler.
     */
    protected function validateRequestHandler(): void
    {
        if (!isset($this->options['request_handler'])) {
            $this->options['request_handler'] = GenericRequestHandler::class;

            return;
        }
        if (!\is_string($this->options['request_handler'])) {
            throw new RuntimeException(sprintf(
                'The request handler must be a string class name, got %s.',
                gettype($this->options['request_handler'])
            ));
        }
        if (!\class_exists($this->options['request_handler'])) {
            throw new RuntimeException(sprintf(
                'The request handler class does not exist: %s',
                $this->options['request_handler']
            ));
        }
        if (!\is_subclass_of($this->options['request_handler'], RequestHandlerInterface::class)) {
            throw new RuntimeException(sprintf(
                'The request handler class must implement "%s"',
                RequestHandlerInterface::class
            ));
        }
    }
}
