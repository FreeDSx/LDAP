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

/**
 * Given a selection of hosts, connect to one and return the TcpClient.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TcpPool
{
    /**
     * @var array
     */
    protected $options = [
        'servers' => [],
        'port' => 389,
        'timeout_connect' => 1,
    ];

    /**
     * @var array
     */
    protected $tcpOpts = [
        'use_ssl',
        'ssl_validate_cert',
        'ssl_allow_self_signed',
        'ssl_ca_cert',
        'ssl_cert',
        'ssl_peer_name',
        'timeout_connect',
        'timeout_read',
    ];

    /**
     * @param array $options
     */
    public function __construct(array $options)
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     * @param null|string $server
     * @return TcpClient
     * @throws ConnectionException
     */
    public function connect(?string $server = null) : TcpClient
    {
        $servers = $server ? [$server] : $this->options['servers'];

        $lastEx = null;
        $tcp = null;
        foreach ($servers as $server) {
            try {
                $tcp = (new TcpClient($server, $this->options['port'], $this->getTcpOptions()))->connect();
                break;
            } catch (\Exception $e) {
                $lastEx = $e;
            }
        }

        if ($tcp === null) {
            throw new ConnectionException(sprintf(
                'Unable to connect to server(s): %s',
                implode(',', $servers)
            ), 0, $lastEx);
        }

        return $tcp;
    }

    /**
     * @return array
     */
    protected function getTcpOptions() : array
    {
        $opts = [];

        foreach ($this->tcpOpts as $name) {
            if (isset($this->options[$name])) {
                $opts[$name] = $this->options[$name];
            }
        }

        return $opts;
    }
}
