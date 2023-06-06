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

final class ClientOptions
{
    private int $version = 3;
    
    private array $servers = [];
    
    private int $port = 389;
    
    private string $transport = 'tcp';
    
    private ?string $baseDn = null;
    
    private int $pageSize = 1000;
    
    private bool $useSsl = false;
    
    private bool $sslValidateCert = true;
    
    private bool $sslAllowSelfSigned = false;
    
    private ?string $sslCaCert = null;
    
    private ?string $sslPeerName = null;
    
    private int $timeoutConnect = 3;
    
    private int $timeoutRead = 10;
    
    private string $referral = 'throw';
    
    private ?ReferralChaserInterface $referralChaser = null;
    
    private int $referralLimit = 10;

    public function getVersion(): int
    {
        return $this->version;
    }

    public function setVersion(int $version): self
    {
        $this->version = $version;

        return $this;
    }

    /**
     * @return string[]
     */
    public function getServers(): array
    {
        return $this->servers;
    }

    /**
     * @param string[] $servers
     */
    public function setServers(array $servers): self
    {
        $this->servers = $servers;

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

    public function getTransport(): string
    {
        return $this->transport;
    }

    public function setTransport(string $transport): self
    {
        $this->transport = $transport;

        return $this;
    }

    public function getBaseDn(): ?string
    {
        return $this->baseDn;
    }

    public function setBaseDn(?string $baseDn): self
    {
        $this->baseDn = $baseDn;

        return $this;
    }

    public function getPageSize(): int
    {
        return $this->pageSize;
    }

    public function setPageSize(int $pageSize): self
    {
        $this->pageSize = $pageSize;

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

    public function isSslValidateCert(): bool
    {
        return $this->sslValidateCert;
    }

    public function setSslValidateCert(bool $sslValidateCert): self
    {
        $this->sslValidateCert = $sslValidateCert;

        return $this;
    }

    public function isSslAllowSelfSigned(): bool
    {
        return $this->sslAllowSelfSigned;
    }

    public function setSslAllowSelfSigned(bool $sslAllowSelfSigned): self
    {
        $this->sslAllowSelfSigned = $sslAllowSelfSigned;

        return $this;
    }

    public function getSslCaCert(): ?string
    {
        return $this->sslCaCert;
    }


    public function setSslCaCert(?string $sslCaCert): self
    {
        $this->sslCaCert = $sslCaCert;

        return $this;
    }

    public function getSslPeerName(): ?string
    {
        return $this->sslPeerName;
    }

    public function setSslPeerName(?string $sslPeerName): self
    {
        $this->sslPeerName = $sslPeerName;

        return $this;
    }

    public function getTimeoutConnect(): int
    {
        return $this->timeoutConnect;
    }

    public function setTimeoutConnect(int $timeoutConnect): self
    {
        $this->timeoutConnect = $timeoutConnect;

        return $this;
    }

    public function getTimeoutRead(): int
    {
        return $this->timeoutRead;
    }

    public function setTimeoutRead(int $timeoutRead): self
    {
        $this->timeoutRead = $timeoutRead;

        return $this;
    }

    public function getReferral(): string
    {
        return $this->referral;
    }

    public function setReferral(string $referral): self
    {
        $this->referral = $referral;

        return $this;
    }

    public function getReferralChaser(): ?ReferralChaserInterface
    {
        return $this->referralChaser;
    }

    public function setReferralChaser(?ReferralChaserInterface $referralChaser): self
    {
        $this->referralChaser = $referralChaser;

        return $this;
    }

    public function getReferralLimit(): int
    {
        return $this->referralLimit;
    }

    public function setReferralLimit(int $referralLimit): self
    {
        $this->referralLimit = $referralLimit;

        return $this;
    }

    /**
     * @return array{version: int, servers: string[], port: int, base_dn: ?string, page_size: int, use_ssl: bool, ssl_validate_cert: bool, ssl_allow_self_signed: bool, ssl_ca_cert: ?string, ssl_peer_name: ?string, timeout_connect: int, timeout_read: int, referral: string, referral_chaser: ?ReferralChaserInterface, referral_limit: int}
     */
    public function toArray(): array
    {
        return [
            'version' => $this->getVersion(),
            'servers' => $this->getServers(),
            'port' => $this->getPort(),
            'transport' => $this->getTransport(),
            'base_dn' => $this->getBaseDn(),
            'page_size' => $this->getPageSize(),
            'use_ssl' => $this->isUseSsl(),
            'ssl_validate_cert' => $this->isSslValidateCert(),
            'ssl_allow_self_signed' => $this->isSslAllowSelfSigned(),
            'ssl_ca_cert' => $this->getSslCaCert(),
            'ssl_peer_name' => $this->getSslPeerName(),
            'timeout_connect' => $this->getTimeoutConnect(),
            'timeout_read' => $this->getTimeoutRead(),
            'referral' => $this->getReferral(),
            'referral_chaser' => $this->getReferralChaser(),
            'referral_limit' => $this->getReferralLimit(),
        ];
    }
}
