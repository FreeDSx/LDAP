<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Tcp;

use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\RuntimeException;

/**
 * TCP client for sending/receiving protocol data.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TcpClient
{
    /**
     * @var resource|null
     */
    protected $tcp;

    /**
     * @var resource|null
     */
    protected $context;

    /**
     * @var string
     */
    protected $host;

    /**
     * @var int
     */
    protected $port;

    /**
     * @var bool
     */
    protected $isEncrypted = false;

    /**
     * @var int
     */
    protected $bufferSize = 8192;

    /**
     * @var array
     */
    protected $options = [
        'use_ssl' => false,
        'ssl_validate_cert' => true,
        'ssl_allow_self_signed' => null,
        'ssl_ca_cert' => null,
        'ssl_peer_name' => null,
        'timeout_connect' => 3,
        'timeout_read' => 15,
        'crypto_type' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT | STREAM_CRYPTO_METHOD_TLS_CLIENT,
    ];

    /**
     * @var array
     */
    protected $sslOpts = [
        'allow_self_signed' => false,
        'verify_peer' => true,
        'verify_peer_name' => true,
        'capture_peer_cert' => true,
        'capture_peer_cert_chain' => true,
    ];

    /**
     * @var null|int
     */
    protected $errorNumber;

    /**
     * @var null|string
     */
    protected $errorMessage;

    /**
     * @var bool
     */
    protected $hasOpenSsl;

    /**
     * @param string $host
     * @param int $port
     * @param array $options
     */
    public function __construct(string $host, int $port = 389, array $options = [])
    {
        $this->hasOpenSsl = extension_loaded('openssl');
        $this->host = $host;
        $this->port = $port;
        $this->options = array_merge($this->options, $options);
    }

    /**
     * @return $this
     * @throws ConnectionException
     */
    public function connect()
    {
        $uri = ($this->options['use_ssl'] ? 'ssl' : 'tcp').'://'.$this->host.':'.$this->port;

        $this->tcp = @stream_socket_client(
            $uri,
            $this->errorNumber,
            $this->errorMessage,
            $this->options['timeout_connect'],
            STREAM_CLIENT_CONNECT,
            $this->createSocketContext()
        );
        if ($this->tcp === false) {
            throw new ConnectionException(sprintf(
                'Unable to connect to %s: %s',
                $this->host,
                $this->errorMessage
            ));
        }
        $this->isEncrypted = $this->options['use_ssl'];

        return $this;
    }

    /**
     * @param bool $block
     * @return string
     */
    public function read(bool $block = true)
    {
        $data = false;

        stream_set_blocking($this->tcp, $block);
        while (strlen($buffer = fread($this->tcp, $this->bufferSize)) > 0) {
            $data .= $buffer;
            if ($block) {
                $block = false;
                stream_set_blocking($this->tcp, false);
            }
        }

        return $data;
    }

    /**
     * @param string $data
     * @return $this
     */
    public function write(string $data)
    {
        fwrite($this->tcp, $data);

        return $this;
    }

    /**
     * Enable/Disable encryption on the TCP connection stream.
     *
     * @param bool $encrypt
     * @return $this
     * @throws ConnectionException
     */
    public function encrypt(bool $encrypt)
    {
        if (!$this->hasOpenSsl) {
            throw new RuntimeException('To encrypt LDAP traffic you must enable the OpenSSL extension.');
        }
        stream_set_blocking($this->tcp, true);
        $result = stream_socket_enable_crypto($this->tcp, $encrypt, $this->options['crypto_type']);
        stream_set_blocking($this->tcp, false);

        if ($result === false) {
            throw new ConnectionException(sprintf(
                'Unable to %s encryption on TCP connection. %s',
                $encrypt ? 'enable' : 'disable',
                $this->errorMessage
            ));
        }
        $this->isEncrypted = $encrypt;

        return $this;
    }

    /**
     * @return bool
     */
    public function isConnected() : bool
    {
        return is_resource($this->tcp);
    }

    /**
     * @return bool
     */
    public function isEncrypted() : bool
    {
        return $this->isEncrypted;
    }

    /**
     * @return $this
     */
    public function close()
    {
        stream_socket_shutdown($this->tcp, STREAM_SHUT_RDWR);
        $this->isEncrypted = false;
        $this->context = null;

        return $this;
    }

    /**
     * @return resource
     */
    protected function createSocketContext()
    {
        $sslOpts = $this->sslOpts;

        if (isset($this->options['ssl_allow_self_signed'])) {
            $sslOpts['allow_self_signed'] = $this->options['ssl_allow_self_signed'];
        }
        if (isset($this->options['ssl_ca_cert'])) {
            $sslOpts['ca_file'] = $this->options['ssl_ca_cert'];
        }
        if (isset($this->options['ssl_peer_name'])) {
            $sslOpts['peer_name'] = $this->options['ssl_peer_name'];
        }

        $sslOpts['crypto_type'] = $this->options['crypto_type'];
        if ($this->options['ssl_validate_cert'] === false) {
            $sslOpts = array_merge($sslOpts, [
                'allow_self_signed' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ]);
        }
        $this->context = stream_context_create([
           'ssl' => $sslOpts,
        ]);

        return $this->context;
    }
}
