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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\AliasResolver;
use FreeDSx\Ldap\Server\Middleware\AliasDereferenceMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class AliasDereferenceMiddlewareTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private AccessControlInterface&MockObject $accessControl;

    private bool $visible = true;

    private AliasDereferenceMiddleware $subject;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->accessControl
            ->method('isEntryVisible')
            ->willReturnCallback(fn(): bool => $this->visible);

        $this->subject = new AliasDereferenceMiddleware(
            new AliasResolver(new InMemoryStorage([
                Entry::fromArray(self::BASE, ['objectClass' => ['top', 'domain'], 'dc' => 'example']),
                Entry::fromArray('cn=target,' . self::BASE, [
                    'objectClass' => ['top', 'person'],
                    'cn' => 'target',
                    'sn' => 'Target',
                ]),
                Entry::fromArray('cn=ptr,' . self::BASE, [
                    'objectClass' => ['top', 'alias', 'extensibleObject'],
                    'cn' => 'ptr',
                    'aliasedObjectName' => 'cn=target,' . self::BASE,
                ]),
            ])),
            $this->accessControl,
        );
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_a_base_naming_an_alias_is_rewritten_to_the_entry_it_names(): void
    {
        $request = $this->searchFor('cn=ptr,' . self::BASE, SearchRequest::DEREF_FINDING_BASE_OBJECT);

        $this->subject->process($this->contextFor($request), $this->next);

        self::assertSame(
            'cn=target,' . self::BASE,
            (string) $request->getBaseDn(),
        );
        self::assertNotNull($this->next->received);
    }

    public function test_deref_always_rewrites_the_base_too(): void
    {
        $request = $this->searchFor('cn=ptr,' . self::BASE, SearchRequest::DEREF_ALWAYS);

        $this->subject->process($this->contextFor($request), $this->next);

        self::assertSame(
            'cn=target,' . self::BASE,
            (string) $request->getBaseDn(),
        );
    }

    public function test_a_base_is_left_alone_when_nothing_is_dereferenced(): void
    {
        $request = $this->searchFor('cn=ptr,' . self::BASE, SearchRequest::DEREF_NEVER);

        $this->subject->process($this->contextFor($request), $this->next);

        self::assertSame(
            'cn=ptr,' . self::BASE,
            (string) $request->getBaseDn(),
        );
    }

    public function test_a_base_naming_no_alias_is_left_alone(): void
    {
        $request = $this->searchFor('cn=target,' . self::BASE, SearchRequest::DEREF_FINDING_BASE_OBJECT);

        $this->subject->process($this->contextFor($request), $this->next);

        self::assertSame(
            'cn=target,' . self::BASE,
            (string) $request->getBaseDn(),
        );
    }

    public function test_a_target_the_identity_cannot_see_is_refused_as_a_missing_base(): void
    {
        $this->visible = false;

        try {
            $this->subject->process(
                $this->contextFor($this->searchFor(
                    'cn=ptr,' . self::BASE,
                    SearchRequest::DEREF_FINDING_BASE_OBJECT,
                )),
                $this->next,
            );
            self::fail('Expected the hidden target to be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::NO_SUCH_OBJECT,
                $e->getCode(),
            );
        }

        self::assertNull(
            $this->next->received,
            'A refused base must not reach the rest of the chain.',
        );
    }

    public function test_a_request_that_is_not_a_search_is_delegated_untouched(): void
    {
        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=ptr,' . self::BASE)),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    private function searchFor(
        string $baseDn,
        int $deref,
    ): SearchRequest {
        return (new SearchRequest(Filters::present('objectClass')))
            ->base($baseDn)
            ->useBaseScope()
            ->setDereferenceAliases($deref);
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(1, $request),
            $this->createMock(TokenInterface::class),
        );
    }
}
