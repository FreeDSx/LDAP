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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization\Requirement;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Initialization\Requirement\SwooleClientCertificatesRequirement;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class SwooleClientCertificatesRequirementTest extends TestCase
{
    private ServerOptions $options;

    private SwooleClientCertificatesRequirement $subject;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults()->setRunnerConfig(RunnerConfig::forSwoole(1));
        $this->subject = new SwooleClientCertificatesRequirement($this->options);
    }

    public function test_the_swoole_runner_is_refused_when_client_certificate_validation_is_on(): void
    {
        $this->options->getNetworkConfig()->setSslValidateCert(true);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The Swoole runner cannot verify client certificates.');

        $this->subject->assertMet();
    }

    public function test_the_swoole_runner_is_refused_when_external_sasl_is_offered(): void
    {
        $this->options->setSaslMechanisms(ServerOptions::SASL_EXTERNAL);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The Swoole runner cannot support the EXTERNAL SASL mechanism.');

        $this->subject->assertMet();
    }

    public function test_the_swoole_runner_is_met_without_client_certificates(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }

    public function test_the_pcntl_runner_is_met_with_client_certificates_and_external_sasl(): void
    {
        $this->options
            ->setRunnerConfig(RunnerConfig::forPcntl())
            ->setSaslMechanisms(ServerOptions::SASL_EXTERNAL)
            ->getNetworkConfig()
            ->setSslValidateCert(true);

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }
}
