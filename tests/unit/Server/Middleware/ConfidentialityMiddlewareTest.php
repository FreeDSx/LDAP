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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Config\ConfidentialityRequirement;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Middleware\ConfidentialityMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class ConfidentialityMiddlewareTest extends TestCase
{
    private ConnectionControl&MockObject $connection;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->connection = $this->createMock(ConnectionControl::class);
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_nothing_is_refused_when_no_requirement_is_configured(): void
    {
        $this->connectionIsEncrypted(false);

        $this->subjectFor(ConfidentialityRequirement::None)->process(
            $this->contextFor(new SimpleBindRequest('cn=foo,dc=bar', 'secret')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    /**
     * @return array<string, array{RequestInterface}>
     */
    public static function credentialBearingRequests(): array
    {
        return [
            'simple bind' => [new SimpleBindRequest('cn=foo,dc=bar', 'secret')],
            'sasl plain' => [new SaslBindRequest(ServerOptions::SASL_PLAIN)],
            'sasl cram-md5' => [new SaslBindRequest(ServerOptions::SASL_CRAM_MD5)],
            'sasl scram-sha-256' => [new SaslBindRequest(ServerOptions::SASL_SCRAM_SHA_256)],
        ];
    }

    #[DataProvider('credentialBearingRequests')]
    public function test_a_credential_bearing_bind_is_refused_in_the_clear(RequestInterface $request): void
    {
        $this->connectionIsEncrypted(false);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONFIDENTIALITY_REQUIRED);

        $this->subjectFor(ConfidentialityRequirement::CredentialBind)->process(
            $this->contextFor($request),
            $this->next,
        );
    }

    #[DataProvider('credentialBearingRequests')]
    public function test_the_same_bind_is_allowed_once_encrypted(RequestInterface $request): void
    {
        $this->connectionIsEncrypted(true);

        $this->subjectFor(ConfidentialityRequirement::CredentialBind)->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    /**
     * @return array<string, array{RequestInterface}>
     */
    public static function requestsCarryingNoCredential(): array
    {
        return [
            'anonymous bind' => [new AnonBindRequest()],
            'sasl external' => [new SaslBindRequest(ServerOptions::SASL_EXTERNAL)],
            'search' => [(new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')],
            'unbind' => [new UnbindRequest()],
        ];
    }

    #[DataProvider('requestsCarryingNoCredential')]
    public function test_a_request_carrying_no_credential_is_allowed_in_the_clear(RequestInterface $request): void
    {
        $this->connectionIsEncrypted(false);

        $this->subjectFor(ConfidentialityRequirement::CredentialBind)->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_a_unix_socket_satisfies_the_requirement_without_encryption(): void
    {
        $this->connectionIsEncrypted(false);

        $this->subjectFor(
            ConfidentialityRequirement::CredentialBind,
            (new NetworkConfig())->setTransport('unix'),
        )->process(
            $this->contextFor(new SimpleBindRequest('cn=foo,dc=bar', 'secret')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_requiring_all_operations_refuses_a_search_in_the_clear(): void
    {
        $this->connectionIsEncrypted(false);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONFIDENTIALITY_REQUIRED);

        $this->subjectFor(ConfidentialityRequirement::AllOperations)->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')),
            $this->next,
        );
    }

    /**
     * @return array<string, array{RequestInterface}>
     */
    public static function requestsThatReachConfidentiality(): array
    {
        return [
            'start tls' => [new ExtendedRequest(ExtendedRequest::OID_START_TLS)],
            'unbind' => [new UnbindRequest()],
            'abandon' => [new AbandonRequest(1)],
        ];
    }

    #[DataProvider('requestsThatReachConfidentiality')]
    public function test_requiring_all_operations_still_allows_reaching_confidentiality(
        RequestInterface $request,
    ): void {
        $this->connectionIsEncrypted(false);

        $this->subjectFor(ConfidentialityRequirement::AllOperations)->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_requiring_all_operations_allows_everything_once_encrypted(): void
    {
        $this->connectionIsEncrypted(true);

        $this->subjectFor(ConfidentialityRequirement::AllOperations)->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_requiring_all_operations_refuses_an_unrelated_extended_operation(): void
    {
        $this->connectionIsEncrypted(false);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONFIDENTIALITY_REQUIRED);

        $this->subjectFor(ConfidentialityRequirement::AllOperations)->process(
            $this->contextFor(new ExtendedRequest(ExtendedRequest::OID_WHOAMI)),
            $this->next,
        );
    }

    private function connectionIsEncrypted(bool $isEncrypted): void
    {
        $this->connection
            ->method('isEncrypted')
            ->willReturn($isEncrypted);
    }

    private function subjectFor(
        ConfidentialityRequirement $requirement,
        ?NetworkConfig $networkConfig = null,
    ): ConfidentialityMiddleware {
        $options = new ServerOptions(networkConfig: $networkConfig ?? new NetworkConfig());
        $options->setRequireConfidentiality($requirement);

        return new ConfidentialityMiddleware(
            $options,
            $this->connection,
        );
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(new LdapMessageRequest(
            1,
            $request,
        ));
    }
}
