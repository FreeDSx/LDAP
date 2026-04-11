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

namespace Tests\Unit\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Entry\Attribute;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use FreeDSx\Ldap\Server\RequestHandler\ProxyBackend;

final class ProxyBackendTest extends TestCase
{
    private LdapClient&MockObject $mockLdap;

    private ProxyBackend $subject;

    protected function setUp(): void
    {
        $this->mockLdap = $this->createMock(LdapClient::class);
        $this->subject = new ProxyBackend();
        $this->subject->setLdapClient($this->mockLdap);
    }

    private function makeContext(int $scope = SearchRequest::SCOPE_WHOLE_SUBTREE): SearchContext
    {
        return new SearchContext(
            baseDn: new Dn('dc=example,dc=com'),
            scope: $scope,
            filter: new PresentFilter('objectClass'),
            attributes: [],
            typesOnly: false,
        );
    }

    public function test_search_yields_entries_from_upstream(): void
    {
        $entry = new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice'));

        $this->mockLdap
            ->expects(self::once())
            ->method('search')
            ->willReturn(new Entries($entry));

        $results = iterator_to_array($this->subject->search($this->makeContext()));

        self::assertCount(1, $results);
        self::assertSame($entry, $results[0]);
    }

    public function test_search_uses_base_scope(): void
    {
        $this->mockLdap
            ->expects(self::once())
            ->method('search')
            ->with(self::callback(fn(SearchRequest $r) => $r->getScope() === SearchRequest::SCOPE_BASE_OBJECT))
            ->willReturn(new Entries());

        iterator_to_array($this->subject->search($this->makeContext(SearchRequest::SCOPE_BASE_OBJECT)));
    }

    public function test_search_uses_single_level_scope(): void
    {
        $this->mockLdap
            ->expects(self::once())
            ->method('search')
            ->with(self::callback(fn(SearchRequest $r) => $r->getScope() === SearchRequest::SCOPE_SINGLE_LEVEL))
            ->willReturn(new Entries());

        iterator_to_array($this->subject->search($this->makeContext(SearchRequest::SCOPE_SINGLE_LEVEL)));
    }

    public function test_search_uses_subtree_scope_by_default(): void
    {
        $this->mockLdap
            ->expects(self::once())
            ->method('search')
            ->with(self::callback(fn(SearchRequest $r) => $r->getScope() === SearchRequest::SCOPE_WHOLE_SUBTREE))
            ->willReturn(new Entries());

        iterator_to_array($this->subject->search($this->makeContext()));
    }

    public function test_get_reads_entry_by_dn(): void
    {
        $entry = new Entry(new Dn('cn=Alice,dc=example,dc=com'));

        $this->mockLdap
            ->expects(self::once())
            ->method('read')
            ->with('cn=Alice,dc=example,dc=com')
            ->willReturn($entry);

        self::assertSame($entry, $this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_verify_password_returns_true_on_successful_bind(): void
    {
        $this->mockLdap
            ->expects(self::once())
            ->method('bind')
            ->with('cn=Alice,dc=example,dc=com', 'secret')
            ->willReturn($this->createMock(LdapMessageResponse::class));

        self::assertTrue($this->subject->verifyPassword('cn=Alice,dc=example,dc=com', 'secret'));
    }

    public function test_verify_password_rethrows_bind_exception_as_operation_exception(): void
    {
        $this->mockLdap
            ->method('bind')
            ->willThrowException(new BindException('Invalid credentials.', ResultCode::INVALID_CREDENTIALS));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->verifyPassword('cn=Alice,dc=example,dc=com', 'wrong');
    }

    public function test_add_sends_add_request_to_upstream(): void
    {
        $entry = Entry::create('cn=Alice,dc=example,dc=com');

        $this->mockLdap
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(self::isInstanceOf(AddRequest::class));

        $this->subject->add(new AddCommand($entry));
    }

    public function test_delete_sends_delete_request_to_upstream(): void
    {
        $this->mockLdap
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(self::isInstanceOf(DeleteRequest::class));

        $this->subject->delete(new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_update_sends_modify_request_to_upstream(): void
    {
        $this->mockLdap
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(self::isInstanceOf(ModifyRequest::class));

        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [Change::replace('cn', 'Alicia')],
        ));
    }

    public function test_move_sends_modify_dn_request_to_upstream(): void
    {
        $this->mockLdap
            ->expects(self::once())
            ->method('sendAndReceive')
            ->with(self::isInstanceOf(ModifyDnRequest::class));

        $this->subject->move(new MoveCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alicia'),
            true,
            null,
        ));
    }
}
