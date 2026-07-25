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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ExternalMechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Sasl\External\ExternalCredentialMapperInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ExternalOptions;
use FreeDSx\Socket\Tls\Certificate;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class ExternalMechanismOptionsBuilderTest extends TestCase
{
    private const CERT_DN = 'cn=client,dc=example,dc=com';

    private AccessControlInterface&MockObject $accessControl;

    private LdapBackendInterface&MockObject $backend;

    private AuthzIdResolver $authzIdResolver;

    protected function setUp(): void
    {
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->authzIdResolver = new AuthzIdResolver(
            $this->accessControl,
            $this->backend,
            $this->createMock(BindNameResolverInterface::class),
            new EventLogger(
                new RecordingLogger(),
                EventLogPolicy::all(),
            ),
        );
    }

    public function test_it_requires_an_encrypted_connection(): void
    {
        $validate = $this->validateClosure($this->builder(
            encrypted: false,
            validateCert: true,
            certificate: null,
            mapped: null,
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONFIDENTIALITY_REQUIRED);

        $validate(null);
    }

    public function test_it_requires_certificate_validation_to_be_enabled(): void
    {
        $validate = $this->validateClosure($this->builder(
            encrypted: true,
            validateCert: false,
            certificate: null,
            mapped: null,
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INAPPROPRIATE_AUTHENTICATION);

        $validate(null);
    }

    public function test_it_requires_a_presented_certificate(): void
    {
        $validate = $this->validateClosure($this->builder(
            encrypted: true,
            validateCert: true,
            certificate: null,
            mapped: null,
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INAPPROPRIATE_AUTHENTICATION);

        $validate(null);
    }

    public function test_it_fails_when_the_mapper_rejects_the_certificate(): void
    {
        $validate = $this->validateClosure($this->builder(
            encrypted: true,
            validateCert: true,
            certificate: $this->certificate(),
            mapped: null,
        ));

        self::assertFalse($validate(null));
    }

    public function test_it_resolves_the_certificate_identity(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(new Entry(new Dn(self::CERT_DN)));

        $builder = $this->builder(
            encrypted: true,
            validateCert: true,
            certificate: $this->certificate(),
            mapped: AuthzId::fromDn(new Dn(self::CERT_DN)),
        );

        // The authzid (if any) is honored later by the SASL exchange, not here.
        self::assertTrue($this->validateClosure($builder)(null));
        self::assertSame(
            self::CERT_DN,
            $builder->getResolvedDn()?->toString(),
        );
    }

    private function builder(
        bool $encrypted,
        bool $validateCert,
        ?Certificate $certificate,
        ?AuthzId $mapped,
    ): ExternalMechanismOptionsBuilder {
        $queue = $this->createMock(ServerQueue::class);
        $queue->method('isEncrypted')
            ->willReturn($encrypted);
        $queue->method('peerCertificate')
            ->willReturn($certificate);

        $mapper = $this->createMock(ExternalCredentialMapperInterface::class);
        $mapper->method('map')
            ->willReturn($mapped);

        return new ExternalMechanismOptionsBuilder(
            $queue,
            new ServerOptions(network: (new NetworkConfig())->setSslValidateCert($validateCert)),
            $mapper,
            $this->authzIdResolver,
        );
    }

    /**
     * @return Closure(?string): bool
     */
    private function validateClosure(ExternalMechanismOptionsBuilder $builder): Closure
    {
        $options = $builder->buildOptions(
            null,
            MechanismName::EXTERNAL,
        );
        if (!$options instanceof ExternalOptions) {
            self::fail('Expected ExternalOptions to be built.');
        }

        $validate = $options->getValidate();
        if ($validate === null) {
            self::fail('Expected a validate closure to be set.');
        }

        return $validate;
    }

    private function certificate(): Certificate
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            self::fail('Failed to generate a private key.');
        }

        $csr = openssl_csr_new(['commonName' => 'client'], $key);
        if (!$csr instanceof OpenSSLCertificateSigningRequest || !$key instanceof OpenSSLAsymmetricKey) {
            self::fail('Failed to generate a certificate signing request.');
        }

        $x509 = openssl_csr_sign($csr, null, $key, 1);
        if (!$x509 instanceof OpenSSLCertificate) {
            self::fail('Failed to sign the certificate.');
        }

        $certificate = Certificate::fromX509($x509);
        if ($certificate === null) {
            self::fail('Failed to parse the generated certificate.');
        }

        return $certificate;
    }
}
