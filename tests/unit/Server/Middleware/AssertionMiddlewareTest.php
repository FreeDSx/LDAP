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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class AssertionMiddlewareTest extends TestCase
{
    use ServerContainerTrait;

    private LdapBackendInterface&MockObject $backend;

    private AssertionMiddleware $subject;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray(
                'cn=foo,dc=bar',
                ['cn' => ['foo']],
            ));

        $this->subject = new AssertionMiddleware(new AssertionEvaluator(
            $this->fromContainer(FilterEvaluatorInterface::class),
            $this->backend,
            new RuleBasedAccessControl(AclRules::fromEmpty()),
        ));
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_it_delegates_when_no_assertion_control_is_present(): void
    {
        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=foo,dc=bar')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_it_delegates_when_the_assertion_matches(): void
    {
        $this->subject->process(
            $this->contextFor(
                new DeleteRequest('cn=foo,dc=bar'),
                Controls::assertion(Filters::equal('cn', 'foo')),
            ),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_it_throws_and_stops_the_chain_when_the_assertion_does_not_match(): void
    {
        try {
            $this->subject->process(
                $this->contextFor(
                    new DeleteRequest('cn=foo,dc=bar'),
                    Controls::assertion(Filters::equal('cn', 'nope')),
                ),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
        }

        self::assertNull(
            $this->next->received,
            'The next handler must not be reached when the assertion fails.',
        );
    }

    public function test_it_resolves_the_search_base_as_the_target(): void
    {
        $search = (new SearchRequest(Filters::equal('cn', 'foo')))
            ->base('cn=foo,dc=bar');

        $this->expectException(OperationException::class);

        $this->subject->process(
            $this->contextFor(
                $search,
                Controls::assertion(Filters::equal('cn', 'nope')),
            ),
            $this->next,
        );
    }

    public function test_it_skips_assertion_on_a_paging_continuation(): void
    {
        $search = (new SearchRequest(Filters::equal('cn', 'foo')))
            ->base('cn=foo,dc=bar');

        $this->subject->process(
            $this->contextFor(
                $search,
                Controls::assertion(Filters::equal('cn', 'nope')),
                new PagingControl(10, 'continuation-cookie'),
            ),
            $this->next,
        );

        self::assertNotNull(
            $this->next->received,
            'A non-matching assertion on a continuation page is not re-evaluated, so the chain proceeds.',
        );
    }

    private function contextFor(
        RequestInterface $request,
        Control ...$controls,
    ): ServerRequestContext {
        return new ServerRequestContext(
            new LdapMessageRequest(
                1,
                $request,
                ...$controls,
            ),
            $this->createMock(TokenInterface::class),
        );
    }
}
