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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use Psr\Log\LoggerInterface;

final class ServerOptions
{
    private string $ip = '0.0.0.0';
    
    private int $port = 389;
    
    private string $unixSocket = '/var/run/ldap.socket';
    
    private string $transport = 'tcp';
    
    private int $idleTimeout = 600;
    
    private bool $requireAuthentication = true;
    
    private bool $allowAnonymous = false;
    
    private bool $useSsl = false;
    
    private ?string $sslCert = null;

    private ?string $sslCertKey = null;

    private ?string $sslCertPassphrase = null;
    
    private ?string $dseAltServer = null;

    /**
     * @var string[]
     */
    private array $dseNamingContexts = ['dc=FreeDSx,dc=local'];

    private string $dseVendorName = 'FreeDSx';
    
    private ?string $dseVendorVersion = null;

    private ?RequestHandlerInterface $requestHandler = null;
    
    private ?RootDseHandlerInterface $rootDseHandler = null;
    
    private ?PagingHandlerInterface $pagingHandler = null;
    
    private ?LoggerInterface $logger = null;

    public function getIp(): string
    {
        return $this->ip;
    }

    public function setIp(string $ip): self
    {
        $this->ip = $ip;

        return $this;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function setPort(int $port): self
    {
        $this->port = $port;

        return $this;
    }

    public function getUnixSocket(): string
    {
        return $this->unixSocket;
    }

    public function setUnixSocket(string $unixSocket): self
    {
        $this->unixSocket = $unixSocket;

        return $this;
    }

    public function getTransport(): string
    {
        return $this->transport;
    }

    public function setTransport(string $transport): self
    {
        $this->transport = $transport;

        return $this;
    }

    public function getIdleTimeout(): int
    {
        return $this->idleTimeout;
    }

    public function setIdleTimeout(int $idleTimeout): self
    {
        $this->idleTimeout = $idleTimeout;

        return $this;
    }

    public function isRequireAuthentication(): bool
    {
        return $this->requireAuthentication;
    }

    public function setRequireAuthentication(bool $requireAuthentication): self
    {
        $this->requireAuthentication = $requireAuthentication;

        return $this;
    }

    public function isAllowAnonymous(): bool
    {
        return $this->allowAnonymous;
    }

    public function setAllowAnonymous(bool $allowAnonymous): self
    {
        $this->allowAnonymous = $allowAnonymous;

        return $this;
    }

    public function isUseSsl(): bool
    {
        return $this->useSsl;
    }

    public function setUseSsl(bool $useSsl): self
    {
        $this->useSsl = $useSsl;

        return $this;
    }

    public function getSslCertKey(): ?string
    {
        return $this->sslCertKey;
    }

    public function setSslCertKey(?string $sslCertKey): self
    {
        $this->sslCertKey = $sslCertKey;

        return $this;
    }

    public function getSslCert(): ?string
    {
        return $this->sslCert;
    }

    public function setSslCert(?string $sslCert): self
    {
        $this->sslCert = $sslCert;

        return $this;
    }

    public function getSslCertPassphrase(): ?string
    {
        return $this->sslCertPassphrase;
    }

    public function setSslCertPassphrase(?string $sslCertPassphrase): self
    {
        $this->sslCertPassphrase = $sslCertPassphrase;

        return $this;
    }

    public function getDseAltServer(): ?string
    {
        return $this->dseAltServer;
    }

    public function setDseAltServer(?string $dseAlServer): self
    {
        $this->dseAltServer = $dseAlServer;

        return $this;
    }

    /**
     * @return string[]
     */
    public function getDseNamingContexts(): array
    {
        return $this->dseNamingContexts;
    }

    public function setDseNamingContexts(string ...$dseNamingContexts): self
    {
        $this->dseNamingContexts = $dseNamingContexts;

        return $this;
    }

    public function getDseVendorName(): string
    {
        return $this->dseVendorName;
    }

    public function setDseVendorName(string $dseVendorName): self
    {
        $this->dseVendorName = $dseVendorName;

        return $this;
    }

    public function getDseVendorVersion(): ?string
    {
        return $this->dseVendorVersion;
    }

    public function setDseVendorVersion(?string $dseVendorVersion): self
    {
        $this->dseVendorVersion = $dseVendorVersion;

        return $this;
    }

    public function getRequestHandler(): ?RequestHandlerInterface
    {
        return $this->requestHandler;
    }

    public function setRequestHandler(?RequestHandlerInterface $requestHandler): self
    {
        $this->requestHandler = $requestHandler;

        return $this;
    }

    public function getRootDseHandler(): ?RootDseHandlerInterface
    {
        return $this->rootDseHandler;
    }

    public function setRootDseHandler(?RootDseHandlerInterface $rootDseHandler): self
    {
        $this->rootDseHandler = $rootDseHandler;
        
        return $this;
    }

    public function getPagingHandler(): ?PagingHandlerInterface
    {
        return $this->pagingHandler;
    }

    public function setPagingHandler(?PagingHandlerInterface $pagingHandler): self
    {
        $this->pagingHandler = $pagingHandler;
        
        return $this;
    }

    public function getLogger(): ?LoggerInterface
    {
        return $this->logger;
    }

    public function setLogger(?LoggerInterface $logger): self
    {
        $this->logger = $logger;
        
        return $this;
    }

    /**
     * @return array{ip: string, port: int, unix_socket: string, transport: string, idle_timeout: int, require_authentication: bool, allow_anonymous: bool, request_handler: ?RequestHandlerInterface, rootdse_handler: ?RootDseHandlerInterface, paging_handler: ?PagingHandlerInterface, logger: ?LoggerInterface, use_ssl: bool, ssl_cert: ?string, ssl_cert_key: ?string, ssl_cert_passphrase: ?string, dse_alt_server: ?string, dse_naming_contexts: string[], dse_vendor_name: string, dse_vendor_version: ?string}
     */
    public function toArray(): array
    {
        return [
            'ip' => $this->getIp(),
            'port' => $this->getPort(),
            'unix_socket' => $this->getUnixSocket(),
            'transport' => $this->getTransport(),
            'idle_timeout' => $this->getIdleTimeout(),
            'require_authentication' => $this->isRequireAuthentication(),
            'allow_anonymous' => $this->isAllowAnonymous(),
            'request_handler' => $this->getRequestHandler(),
            'rootdse_handler' => $this->getRootDseHandler(),
            'paging_handler' => $this->getPagingHandler(),
            'logger' => $this->getLogger(),
            'use_ssl' => $this->isUseSsl(),
            'ssl_cert' => $this->getSslCert(),
            'ssl_cert_key' => $this->getSslCertKey(),
            'ssl_cert_passphrase' => $this->getSslCertPassphrase(),
            'dse_alt_server' => $this->getDseAltServer(),
            'dse_naming_contexts' => $this->getDseNamingContexts(),
            'dse_vendor_name' => $this->getDseVendorName(),
            'dse_vendor_version' => $this->getDseVendorVersion(),
        ];
    }
}
