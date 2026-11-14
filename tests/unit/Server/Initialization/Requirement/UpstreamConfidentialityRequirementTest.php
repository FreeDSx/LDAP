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

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use FreeDSx\Ldap\Server\Initialization\Requirement\UpstreamConfidentialityRequirement;
use PHPUnit\Framework\TestCase;

final class UpstreamConfidentialityRequirementTest extends TestCase
{
    public function test_an_upstream_that_cannot_be_encrypted_is_refused_when_confidentiality_is_required(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The upstream connection is not encrypted.');

        (new UpstreamConfidentialityRequirement(new ProxyOptions(
            serverOptions: new ProxyServerOptions(),
            requireUpstreamConfidentiality: true,
        )))->assertMet();
    }

    public function test_an_upstream_using_start_tls_is_met_when_confidentiality_is_required(): void
    {
        $this->expectNotToPerformAssertions();

        (new UpstreamConfidentialityRequirement(new ProxyOptions(
            serverOptions: new ProxyServerOptions(),
            useStartTls: true,
            requireUpstreamConfidentiality: true,
        )))->assertMet();
    }

    public function test_an_upstream_using_ldaps_is_met_when_confidentiality_is_required(): void
    {
        $this->expectNotToPerformAssertions();

        (new UpstreamConfidentialityRequirement(new ProxyOptions(
            serverOptions: new ProxyServerOptions(),
            clientOptions: (new ClientOptions())->setUseSsl(true),
            requireUpstreamConfidentiality: true,
        )))->assertMet();
    }

    public function test_an_upstream_that_cannot_be_encrypted_is_met_when_confidentiality_is_not_required(): void
    {
        $this->expectNotToPerformAssertions();

        (new UpstreamConfidentialityRequirement(new ProxyOptions(new ProxyServerOptions())))->assertMet();
    }
}
