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
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\HandlerRouteResolverInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class OperationAuthorizationMiddlewareTest extends TestCase
{
    private const SUBSCHEMA_DN = 'cn=Subschema';

    private HandlerRouteResolverInterface&MockObject $resolver;

    private AccessControlInterface&MockObject $accessControl;

    private TokenInterface&MockObject $token;

    private OperationAuthorizationMiddleware $subject;

    private RecordingMiddlewareHandler $next;

    /**
     * @var list<array{OperationType, string}>
     */
    private array $authorizedOperations = [];

    protected function setUp(): void
    {
        $this->resolver = $this->createMock(HandlerRouteResolverInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->token = $this->createMock(TokenInterface::class);
        $this->subject = new OperationAuthorizationMiddleware(
            $this->resolver,
            $this->accessControl,
            new Dn(self::SUBSCHEMA_DN),
        );
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_search_route_authorizes_the_search_operation_then_continues(): void
    {
        $this->routeResolvesTo(HandlerId::Search);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeOperation')
            ->with(
                OperationType::Search,
                $this->token,
                self::isInstanceOf(Dn::class),
            );

        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_search_route_denial_blocks_dispatch(): void
    {
        $this->routeResolvesTo(HandlerId::Paging);
        $this->accessControl
            ->method('authorizeOperation')
            ->willThrowException($this->denied());

        try {
            $this->subject->process(
                $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNull(
            $this->next->received,
            'Dispatch must be blocked on denial.',
        );
    }

    public function test_monitor_route_authorizes_a_search_against_the_monitor_dn(): void
    {
        $this->routeResolvesTo(HandlerId::Monitor);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeOperation')
            ->with(
                OperationType::Search,
                $this->token,
                self::isInstanceOf(Dn::class),
            );

        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base('cn=monitor')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_monitor_route_denial_blocks_dispatch(): void
    {
        $this->routeResolvesTo(HandlerId::Monitor);
        $this->accessControl
            ->method('authorizeOperation')
            ->willThrowException($this->denied());

        try {
            $this->subject->process(
                $this->contextFor((new SearchRequest(Filters::present('cn')))->base('cn=monitor')),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException) {
        }

        self::assertNull($this->next->received);
    }

    public function test_subschema_route_authorizes_a_search_against_the_configured_subschema_dn(): void
    {
        $this->routeResolvesTo(HandlerId::Subschema);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeOperation')
            ->with(
                OperationType::Search,
                $this->token,
                self::callback(
                    static fn(Dn $dn): bool => $dn->toString() === self::SUBSCHEMA_DN,
                ),
            );

        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base(self::SUBSCHEMA_DN)),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_subschema_route_denial_blocks_dispatch(): void
    {
        $this->routeResolvesTo(HandlerId::Subschema);
        $this->accessControl
            ->method('authorizeOperation')
            ->willThrowException($this->denied());

        try {
            $this->subject->process(
                $this->contextFor((new SearchRequest(Filters::present('cn')))->base(self::SUBSCHEMA_DN)),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException) {
        }

        self::assertNull($this->next->received);
    }

    /**
     * RFC 4513 section 5.2.1.5 has servers let even anonymous clients read supportedSASLMechanisms before
     * authenticating, so this route is exempt on purpose rather than by omission.
     */
    public function test_the_root_dse_route_is_deliberately_never_gated(): void
    {
        $this->routeResolvesTo(HandlerId::RootDse);
        $this->accessControl
            ->expects(self::never())
            ->method('authorizeOperation');

        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('objectClass')))->base('')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    /**
     * A rename in place still moves the entry to a new DN, which a rule may name.
     */
    public function test_dispatch_route_authorizes_modify_dn_against_source_and_destination(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->recordAuthorizedOperations();

        $this->subject->process(
            $this->contextFor(new ModifyDnRequest('cn=foo,dc=bar', 'cn=baz', true)),
            $this->next,
        );

        self::assertSame(
            [
                'cn=foo,dc=bar',
                'cn=baz,dc=bar',
            ],
            $this->authorizedModifyDnTargets(),
        );
    }

    public function test_dispatch_route_authorizes_modify_dn_against_source_destination_and_new_superior(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->recordAuthorizedOperations();

        $this->subject->process(
            $this->contextFor(new ModifyDnRequest('cn=foo,dc=bar', 'cn=baz', true, 'ou=other,dc=bar')),
            $this->next,
        );

        self::assertSame(
            [
                'cn=foo,dc=bar',
                'cn=baz,ou=other,dc=bar',
                'ou=other,dc=bar',
            ],
            $this->authorizedModifyDnTargets(),
        );
    }

    public function test_dispatch_route_add_attribute_denial_blocks_dispatch(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeAttribute')
            ->willThrowException($this->denied());

        $message = $this->contextFor(new AddRequest(Entry::create(
            'cn=foo,dc=bar',
            ['userpassword' => 'secret'],
        )));

        try {
            $this->subject->process($message, $this->next);
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNull($this->next->received);
    }

    public function test_dispatch_route_compare_attribute_denial_blocks_dispatch(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeAttribute')
            ->willThrowException($this->denied());

        $message = $this->contextFor(new CompareRequest(
            'cn=foo,dc=bar',
            Filters::equal('userpassword', 'secret'),
        ));

        try {
            $this->subject->process($message, $this->next);
            self::fail('Expected an OperationException.');
        } catch (OperationException) {
        }

        self::assertNull($this->next->received);
    }

    public function test_dispatch_route_compare_normalizes_attribute_options_for_authorization(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeAttribute')
            ->with(
                self::anything(),
                self::anything(),
                'userPassword',
                AttributeAccess::Read,
            );

        $message = $this->contextFor(new CompareRequest(
            'cn=foo,dc=bar',
            Filters::equal('userPassword;binary', 'secret'),
        ));

        $this->subject->process(
            $message,
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_dispatch_route_authorizes_a_privileged_control_against_the_target(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeControl')
            ->with(
                $this->token,
                self::isInstanceOf(Dn::class),
                Control::OID_RELAX_RULES,
            );

        $message = new LdapMessageRequest(
            1,
            new DeleteRequest('cn=foo,dc=bar'),
            new Control(Control::OID_RELAX_RULES, criticality: true),
        );

        $this->subject->process(
            new ServerRequestContext($message, $this->token),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_dispatch_gates_a_control_configured_as_privileged(): void
    {
        $subject = new OperationAuthorizationMiddleware(
            $this->resolver,
            $this->accessControl,
            new Dn(self::SUBSCHEMA_DN),
            [Control::OID_SUBTREE_DELETE],
        );
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeControl')
            ->with(
                $this->token,
                self::isInstanceOf(Dn::class),
                Control::OID_SUBTREE_DELETE,
            );

        $message = new LdapMessageRequest(
            1,
            new DeleteRequest('cn=foo,dc=bar'),
            new Control(Control::OID_SUBTREE_DELETE, criticality: true),
        );

        $subject->process(
            new ServerRequestContext($message, $this->token),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_dispatch_does_not_gate_a_control_outside_the_privileged_set(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->expects(self::never())
            ->method('authorizeControl');

        $message = new LdapMessageRequest(
            1,
            new DeleteRequest('cn=foo,dc=bar'),
            new Control(Control::OID_SUBTREE_DELETE, criticality: true),
        );

        $this->subject->process(
            new ServerRequestContext($message, $this->token),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_sync_route_authorizes_the_sync_control_against_the_base_dn(): void
    {
        $subject = new OperationAuthorizationMiddleware(
            $this->resolver,
            $this->accessControl,
            new Dn(self::SUBSCHEMA_DN),
            [Control::OID_SYNC_REQUEST],
        );
        $this->routeResolvesTo(HandlerId::Sync);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeControl')
            ->with(
                $this->token,
                self::isInstanceOf(Dn::class),
                Control::OID_SYNC_REQUEST,
            );

        $message = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('dc=foo,dc=bar'),
            new Control(Control::OID_SYNC_REQUEST, criticality: true),
        );

        $subject->process(
            new ServerRequestContext($message, $this->token),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_sync_route_control_denial_blocks_dispatch(): void
    {
        $subject = new OperationAuthorizationMiddleware(
            $this->resolver,
            $this->accessControl,
            new Dn(self::SUBSCHEMA_DN),
            [Control::OID_SYNC_REQUEST],
        );
        $this->routeResolvesTo(HandlerId::Sync);
        $this->accessControl
            ->method('authorizeControl')
            ->willThrowException($this->denied());

        $message = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('dc=foo,dc=bar'),
            new Control(Control::OID_SYNC_REQUEST, criticality: true),
        );

        try {
            $subject->process(
                new ServerRequestContext($message, $this->token),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNull(
            $this->next->received,
            'Dispatch must be blocked when the sync control is denied.',
        );
    }

    #[DataProvider('unauthorizedRoutes')]
    public function test_routes_without_operation_authorization_are_not_gated(HandlerId $routeId): void
    {
        $this->routeResolvesTo($routeId);
        $this->accessControl
            ->expects(self::never())
            ->method('authorizeOperation');

        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base('')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    /**
     * @return iterable<string, array{HandlerId}>
     */
    public static function unauthorizedRoutes(): iterable
    {
        yield 'whoami' => [HandlerId::WhoAmI];
        yield 'start tls' => [HandlerId::StartTls];
        yield 'cancel' => [HandlerId::Cancel];
        yield 'unbind' => [HandlerId::Unbind];
    }

    public function test_a_critical_pre_read_control_authorizes_a_read_of_the_target(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->expects(self::atLeastOnce())
            ->method('authorizeOperation')
            ->willReturnCallback(function (OperationType $operation, TokenInterface $token, Dn $dn): void {
                if ($operation === OperationType::Search) {
                    self::assertSame(
                        'cn=foo,dc=bar',
                        $dn->toString(),
                    );
                }
            });

        $this->subject->process(
            $this->contextFor(
                new DeleteRequest('cn=foo,dc=bar'),
                $this->critical(Controls::preRead()),
            ),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_a_critical_post_read_on_a_rename_authorizes_a_read_of_the_resulting_dn(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $seen = [];
        $this->accessControl
            ->method('authorizeOperation')
            ->willReturnCallback(function (OperationType $operation, TokenInterface $token, Dn $dn) use (&$seen): void {
                if ($operation === OperationType::Search) {
                    $seen[] = $dn->toString();
                }
            });

        $this->subject->process(
            $this->contextFor(
                new ModifyDnRequest(
                    'cn=foo,dc=bar',
                    'cn=bar',
                    true,
                ),
                $this->critical(Controls::postRead()),
            ),
            $this->next,
        );

        self::assertSame(
            ['cn=bar,dc=bar'],
            $seen,
        );
    }

    public function test_a_read_denial_blocks_a_write_carrying_a_critical_pre_read_control(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeOperation')
            ->willReturnCallback(function (OperationType $operation): void {
                if ($operation === OperationType::Search) {
                    throw $this->denied();
                }
            });

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->process(
            $this->contextFor(
                new DeleteRequest('cn=foo,dc=bar'),
                $this->critical(Controls::preRead()),
            ),
            $this->next,
        );
    }

    public function test_a_non_critical_pre_read_control_authorizes_no_read(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeOperation')
            ->willReturnCallback(static function (OperationType $operation): void {
                self::assertNotSame(
                    OperationType::Search,
                    $operation,
                );
            });

        $this->subject->process(
            $this->contextFor(
                new DeleteRequest('cn=foo,dc=bar'),
                Controls::preRead(),
            ),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_a_non_critical_assertion_still_authorizes_a_read_of_the_target(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $seen = [];
        $this->accessControl
            ->method('authorizeOperation')
            ->willReturnCallback(function (OperationType $operation, TokenInterface $token, Dn $dn) use (&$seen): void {
                if ($operation === OperationType::Search) {
                    $seen[] = $dn->toString();
                }
            });
        $assertion = Controls::assertion(Filters::equal('cn', 'foo'));
        $assertion->setCriticality(false);

        $this->subject->process(
            $this->contextFor(
                new DeleteRequest('cn=foo,dc=bar'),
                $assertion,
            ),
            $this->next,
        );

        self::assertSame(
            ['cn=foo,dc=bar'],
            $seen,
        );
    }

    public function test_a_request_without_a_read_bearing_control_authorizes_no_read(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeOperation')
            ->willReturnCallback(static function (OperationType $operation): void {
                self::assertNotSame(
                    OperationType::Search,
                    $operation,
                );
            });

        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=foo,dc=bar')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    /**
     * @return array<string, array{HandlerId, RequestInterface}>
     */
    public static function routesCarryingAPrivilegedControl(): array
    {
        return [
            'compare' => [HandlerId::Dispatch, new CompareRequest('cn=foo,dc=bar', Filters::equal('cn', 'foo'))],
            'extended' => [HandlerId::UnsupportedExtended, new ExtendedRequest('1.2.3.4')],
            'search' => [HandlerId::Search, (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')],
            'paging' => [HandlerId::Paging, (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')],
            'sync' => [HandlerId::Sync, (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')],
        ];
    }

    #[DataProvider('routesCarryingAPrivilegedControl')]
    public function test_a_privileged_control_is_gated_on_every_route(
        HandlerId $routeId,
        RequestInterface $request,
    ): void {
        $this->routeResolvesTo($routeId);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeControl')
            ->with(
                $this->token,
                self::isInstanceOf(Dn::class),
                Control::OID_RELAX_RULES,
            );

        $this->subject->process(
            $this->contextFor(
                $request,
                Controls::relaxRules(),
            ),
            $this->next,
        );
    }

    #[DataProvider('routesCarryingAPrivilegedControl')]
    public function test_a_privileged_control_denial_blocks_every_route(
        HandlerId $routeId,
        RequestInterface $request,
    ): void {
        $this->routeResolvesTo($routeId);
        $this->accessControl
            ->method('authorizeControl')
            ->willThrowException($this->denied());

        try {
            $this->subject->process(
                $this->contextFor(
                    $request,
                    Controls::relaxRules(),
                ),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNull(
            $this->next->received,
            'Dispatch must be blocked on denial.',
        );
    }

    public function test_a_request_naming_no_entry_gates_the_control_against_the_root(): void
    {
        $this->routeResolvesTo(HandlerId::UnsupportedExtended);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeControl')
            ->with(
                $this->token,
                self::callback(static fn(Dn $dn): bool => $dn->toString() === ''),
                Control::OID_RELAX_RULES,
            );

        $this->subject->process(
            $this->contextFor(
                new ExtendedRequest('1.2.3.4'),
                Controls::relaxRules(),
            ),
            $this->next,
        );
    }

    public function test_the_sync_control_is_gated_against_the_search_base(): void
    {
        $subject = new OperationAuthorizationMiddleware(
            $this->resolver,
            $this->accessControl,
            new Dn(self::SUBSCHEMA_DN),
            [Control::OID_SYNC_REQUEST],
        );
        $this->routeResolvesTo(HandlerId::Sync);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeControl')
            ->with(
                $this->token,
                self::callback(static fn(Dn $dn): bool => $dn->toString() === 'dc=foo,dc=bar'),
                Control::OID_SYNC_REQUEST,
            );

        $subject->process(
            $this->contextFor(
                (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
                new Control(Control::OID_SYNC_REQUEST),
            ),
            $this->next,
        );
    }

    public function test_a_rename_authorizes_a_write_of_the_new_rdn_attribute_at_the_resulting_dn(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $seen = [];
        $this->accessControl
            ->method('authorizeAttribute')
            ->willReturnCallback(
                function (TokenInterface $token, Dn $dn, string $attribute, AttributeAccess $access) use (&$seen): void {
                    $seen[] = $dn->toString() . '/' . $attribute . '/' . $access->name;
                },
            );

        $this->subject->process(
            $this->contextFor(new ModifyDnRequest(
                'cn=foo,dc=bar',
                'uid=bar',
                false,
            )),
            $this->next,
        );

        self::assertSame(
            ['uid=bar,dc=bar/uid/Write'],
            $seen,
        );
    }

    public function test_a_rename_deleting_the_old_rdn_authorizes_a_write_of_both_attributes(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $seen = [];
        $this->accessControl
            ->method('authorizeAttribute')
            ->willReturnCallback(
                function (TokenInterface $token, Dn $dn, string $attribute) use (&$seen): void {
                    $seen[] = $attribute;
                },
            );

        $this->subject->process(
            $this->contextFor(new ModifyDnRequest(
                'cn=foo,dc=bar',
                'uid=bar',
                true,
            )),
            $this->next,
        );

        self::assertSame(
            ['uid', 'cn'],
            $seen,
        );
    }

    public function test_a_rename_authorizes_every_component_of_a_multivalued_rdn(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $seen = [];
        $this->accessControl
            ->method('authorizeAttribute')
            ->willReturnCallback(
                function (TokenInterface $token, Dn $dn, string $attribute) use (&$seen): void {
                    $seen[] = $attribute;
                },
            );

        $this->subject->process(
            $this->contextFor(new ModifyDnRequest(
                'cn=foo,dc=bar',
                'cn=bar+uid=baz',
                false,
            )),
            $this->next,
        );

        self::assertSame(
            ['cn', 'uid'],
            $seen,
        );
    }

    public function test_an_option_bearing_rdn_is_refused_when_the_base_attribute_write_is_denied(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeAttribute')
            ->willReturnCallback(
                function (TokenInterface $token, Dn $dn, string $attribute): void {
                    if (Attribute::normalizeName($attribute) === 'userpassword') {
                        throw $this->denied();
                    }
                },
            );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->process(
            $this->contextFor(new ModifyDnRequest(
                'cn=foo,dc=bar',
                'userPassword;x=hunter2',
                false,
            )),
            $this->next,
        );
    }

    public function test_a_denied_rdn_attribute_write_blocks_the_rename(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeAttribute')
            ->willThrowException($this->denied());

        try {
            $this->subject->process(
                $this->contextFor(new ModifyDnRequest(
                    'cn=foo,dc=bar',
                    'uid=bar',
                    false,
                )),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNull($this->next->received);
    }

    private function critical(Control $control): Control
    {
        return $control->setCriticality(true);
    }

    private function routeResolvesTo(HandlerId $id): void
    {
        $this->resolver
            ->method('routeIdFor')
            ->willReturn($id);
    }

    private function recordAuthorizedOperations(): void
    {
        $this->accessControl
            ->method('authorizeOperation')
            ->willReturnCallback(function (
                OperationType $operation,
                TokenInterface $token,
                Dn $dn,
            ): void {
                $this->authorizedOperations[] = [
                    $operation,
                    $dn->toString(),
                ];
            });
    }

    /**
     * @return list<string>
     */
    private function authorizedModifyDnTargets(): array
    {
        $targets = [];

        foreach ($this->authorizedOperations as [$operation, $dn]) {
            if ($operation === OperationType::ModifyDn) {
                $targets[] = $dn;
            }
        }

        return $targets;
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
            $this->token,
        );
    }

    private function denied(): OperationException
    {
        return new OperationException(
            'Access denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );
    }
}
