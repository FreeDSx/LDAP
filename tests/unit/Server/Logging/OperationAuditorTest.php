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

namespace Tests\Unit\FreeDSx\Ldap\Server\Logging;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationDisposition;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class OperationAuditorTest extends TestCase
{
    private const TARGET_DN = 'cn=Bob,dc=example,dc=com';

    private const ACTOR_DN = 'cn=alice,dc=example,dc=com';

    private const MESSAGE_ID = 7;

    private RecordingLogger $recordingLogger;

    private OperationAuditor $subject;

    private BindToken $token;

    protected function setUp(): void
    {
        $this->recordingLogger = new RecordingLogger();
        $this->subject = new OperationAuditor(new EventLogger(
            $this->recordingLogger,
            EventLogPolicy::all(),
        ));
        $this->token = BindToken::fromDn(
            self::ACTOR_DN,
        );
    }

    /**
     * @param array<string, mixed> $expectedTarget
     */
    #[DataProvider('provideWriteSuccessCases')]
    public function test_record_write_success_emits_per_operation_event(
        RequestInterface $request,
        string $expectedEvent,
        string $expectedOperation,
        array $expectedTarget,
    ): void {
        $this->subject->recordWriteSuccess(
            self::wrap($request),
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            $expectedEvent,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            self::MESSAGE_ID,
            $record['context'][EventContext::MESSAGE_ID],
        );
        self::assertSame(
            $expectedOperation,
            $record['context'][EventContext::OPERATION],
        );
        self::assertSame(
            $expectedTarget,
            $record['context'][EventContext::TARGET],
        );
        self::assertSame(
            [
                EventContext::USERNAME => self::ACTOR_DN,
                EventContext::DN => self::ACTOR_DN,
            ],
            $record['context'][EventContext::SUBJECT],
        );
        self::assertSame(
            [],
            $record['context'][EventContext::CONTROL_OIDS],
        );
    }

    /**
     * @return array<string, array{RequestInterface, string, string, array<string, mixed>}>
     */
    public static function provideWriteSuccessCases(): array
    {
        return [
            'add' => [
                new AddRequest(new Entry(
                    new Dn(self::TARGET_DN),
                    new Attribute('cn', 'Bob'),
                )),
                ServerEvent::EntryAdded->value,
                'add',
                [EventContext::DN => self::TARGET_DN],
            ],
            'modify' => [
                new ModifyRequest(
                    self::TARGET_DN,
                    Change::replace('cn', 'Bob'),
                ),
                ServerEvent::EntryModified->value,
                'modify',
                [EventContext::DN => self::TARGET_DN],
            ],
            'delete' => [
                new DeleteRequest(self::TARGET_DN),
                ServerEvent::EntryDeleted->value,
                'delete',
                [EventContext::DN => self::TARGET_DN],
            ],
            'modify_dn' => [
                new ModifyDnRequest(
                    self::TARGET_DN,
                    'cn=Robert',
                    true,
                ),
                ServerEvent::EntryRenamed->value,
                'modify_dn',
                [
                    EventContext::DN => self::TARGET_DN,
                    EventContext::NEW_RDN => 'cn=Robert',
                ],
            ],
        ];
    }

    public function test_modify_dn_target_includes_new_rdn_and_new_superior(): void
    {
        $request = new ModifyDnRequest(
            self::TARGET_DN,
            'cn=Robert',
            true,
            'ou=staff,dc=example,dc=com',
        );

        $this->subject->recordWriteSuccess(
            self::wrap($request),
            $this->token,
        );

        self::assertSame(
            [
                EventContext::DN => self::TARGET_DN,
                EventContext::NEW_RDN => 'cn=Robert',
                EventContext::NEW_SUPERIOR_DN => 'ou=staff,dc=example,dc=com',
            ],
            $this->onlyRecord()['context'][EventContext::TARGET],
        );
    }

    public function test_record_compare_completed_carries_attribute_and_match(): void
    {
        $request = new CompareRequest(
            self::TARGET_DN,
            new EqualityFilter('cn', 'Bob'),
        );

        $this->subject->recordCompareCompleted(
            self::wrap($request),
            match: true,
            token: $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::CompareCompleted->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertTrue($record['context'][EventContext::MATCH]);
        self::assertSame(
            [
                EventContext::DN => self::TARGET_DN,
                EventContext::ATTRIBUTE => 'cn',
            ],
            $record['context'][EventContext::TARGET],
        );
    }

    public function test_record_search_success_carries_entries_and_target(): void
    {
        $request = (new SearchRequest(Filters::present('cn')))->base('dc=example,dc=com');

        $this->subject->recordSearchSuccess(
            self::wrap($request),
            42,
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::SearchAuthorized->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            42,
            $record['context'][EventContext::ENTRIES_RETURNED],
        );
        self::assertSame(
            [
                EventContext::BASE_DN => 'dc=example,dc=com',
                EventContext::SCOPE => $request->getScope(),
            ],
            $record['context'][EventContext::TARGET],
        );
    }

    public function test_record_search_failure_discriminates_a_read_denial(): void
    {
        $request = (new SearchRequest(Filters::present('cn')))->base('dc=example,dc=com');

        $this->subject->recordSearchFailure(
            self::wrap($request),
            new OperationException(
                'Denied',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ),
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::AuthorizationDeniedRead->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            $record['context'][EventContext::RESULT_CODE],
        );
    }

    public function test_record_compare_failure_is_a_read_denial_carrying_the_attribute(): void
    {
        $request = new CompareRequest(
            self::TARGET_DN,
            new EqualityFilter('userPassword', 'secret'),
        );

        $this->subject->recordCompareFailure(
            self::wrap($request),
            new OperationException(
                'Denied',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ),
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::AuthorizationDeniedRead->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            [
                EventContext::DN => self::TARGET_DN,
                EventContext::ATTRIBUTE => 'userPassword',
            ],
            $record['context'][EventContext::TARGET],
        );
    }

    public function test_record_password_modify_success_carries_target(): void
    {
        $this->subject->recordPasswordModifySuccess(
            self::wrap(new PasswordModifyRequest(self::TARGET_DN)),
            new Dn(self::TARGET_DN),
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::PasswordModifySuccess->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            [EventContext::DN => self::TARGET_DN],
            $record['context'][EventContext::TARGET],
        );
    }

    public function test_record_password_modify_failure_falls_back_to_password_modify_failed(): void
    {
        $this->subject->recordPasswordModifyFailure(
            self::wrap(new PasswordModifyRequest(self::TARGET_DN)),
            new OperationException(
                'Boom',
                ResultCode::OPERATIONS_ERROR,
            ),
            new Dn(self::TARGET_DN),
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::PasswordModifyFailed->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            [EventContext::DN => self::TARGET_DN],
            $record['context'][EventContext::TARGET],
        );
    }

    public function test_record_password_modify_failure_omits_target_when_unresolved(): void
    {
        $this->subject->recordPasswordModifyFailure(
            self::wrap(new PasswordModifyRequest()),
            new OperationException(
                'Boom',
                ResultCode::OPERATIONS_ERROR,
            ),
            null,
            $this->token,
        );

        self::assertArrayNotHasKey(
            EventContext::TARGET,
            $this->onlyRecord()['context'],
        );
    }

    public function test_control_oids_lists_attached_controls(): void
    {
        $message = new LdapMessageRequest(
            self::MESSAGE_ID,
            new DeleteRequest(self::TARGET_DN),
            new Control('1.2.3.4', criticality: true),
            new Control('5.6.7.8', criticality: false),
        );

        $this->subject->recordWriteSuccess(
            $message,
            $this->token,
        );

        self::assertSame(
            ['1.2.3.4', '5.6.7.8'],
            $this->onlyRecord()['context'][EventContext::CONTROL_OIDS],
        );
    }

    public function test_record_failure_discriminates_acl_denial(): void
    {
        $request = new ModifyRequest(
            self::TARGET_DN,
            Change::replace('cn', 'Bob'),
        );

        $this->subject->recordFailure(
            self::wrap($request),
            new OperationException(
                'Denied',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ),
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::AuthorizationDeniedWrite->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            self::MESSAGE_ID,
            $record['context'][EventContext::MESSAGE_ID],
        );
        self::assertSame(
            'modify',
            $record['context'][EventContext::OPERATION],
        );
        self::assertSame(
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            $record['context'][EventContext::RESULT_CODE],
        );
        self::assertSame(
            'Denied',
            $record['context'][EventContext::REASON],
        );
    }

    public function test_record_failure_discriminates_critical_control(): void
    {
        $message = new LdapMessageRequest(
            self::MESSAGE_ID,
            new DeleteRequest(self::TARGET_DN),
            new Control('1.2.3.4', criticality: true),
        );

        $this->subject->recordFailure(
            $message,
            new OperationException(
                'Critical control not supported.',
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            ),
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::CriticalControlRejected->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            ['1.2.3.4'],
            $record['context'][EventContext::CONTROL_OIDS],
        );
    }

    #[DataProvider('provideSchemaCodes')]
    public function test_record_failure_does_not_emit_schema_violation_for_schema_codes(int $resultCode): void
    {
        $this->subject->recordFailure(
            self::wrap(new AddRequest(new Entry(
                new Dn(self::TARGET_DN),
                new Attribute('cn', 'Bob'),
            ))),
            new OperationException(
                'Schema problem',
                $resultCode,
            ),
            $this->token,
        );

        self::assertSame(
            [],
            $this->recordingLogger->records,
        );
    }

    /**
     * @return array<string, array{int}>
     */
    public static function provideSchemaCodes(): array
    {
        return [
            'object class violation' => [ResultCode::OBJECT_CLASS_VIOLATION],
            'invalid attribute syntax' => [ResultCode::INVALID_ATTRIBUTE_SYNTAX],
            'not allowed on RDN' => [ResultCode::NOT_ALLOWED_ON_RDN],
            'naming violation' => [ResultCode::NAMING_VIOLATION],
            'attribute or value exists' => [ResultCode::ATTRIBUTE_OR_VALUE_EXISTS],
        ];
    }

    public function test_record_failure_is_silent_for_benign_codes(): void
    {
        // NO_SUCH_OBJECT and ENTRY_ALREADY_EXISTS are normal client mistakes; not audit-worthy.
        $this->subject->recordFailure(
            self::wrap(new DeleteRequest(self::TARGET_DN)),
            new OperationException(
                'Not found',
                ResultCode::NO_SUCH_OBJECT,
            ),
            $this->token,
        );
        $this->subject->recordFailure(
            self::wrap(new AddRequest(new Entry(
                new Dn(self::TARGET_DN),
                new Attribute('cn', 'Bob'),
            ))),
            new OperationException(
                'Exists',
                ResultCode::ENTRY_ALREADY_EXISTS,
            ),
            $this->token,
        );

        self::assertSame(
            [],
            $this->recordingLogger->records,
        );
    }

    #[DataProvider('provideDispositions')]
    public function test_record_schema_violations_tags_validation_mode(
        SchemaViolationDisposition $disposition,
        string $expectedMode,
    ): void {
        $violations = new SchemaViolations();
        $violations->record(
            new OperationException(
                'Required attribute "sn" is missing.',
                ResultCode::OBJECT_CLASS_VIOLATION,
            ),
            $disposition,
        );

        $this->subject->recordSchemaViolations(
            $violations,
            self::wrap(new AddRequest(new Entry(
                new Dn(self::TARGET_DN),
                new Attribute('cn', 'Bob'),
            ))),
            $this->token,
        );

        $record = $this->onlyRecord();
        self::assertSame(
            ServerEvent::SchemaViolation->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            $expectedMode,
            $record['context'][EventContext::VALIDATION_MODE],
        );
        self::assertSame(
            'add',
            $record['context'][EventContext::OPERATION],
        );
        self::assertSame(
            ResultCode::OBJECT_CLASS_VIOLATION,
            $record['context'][EventContext::RESULT_CODE],
        );
        self::assertSame(
            'Required attribute "sn" is missing.',
            $record['context'][EventContext::REASON],
        );
        self::assertSame(
            [EventContext::DN => self::TARGET_DN],
            $record['context'][EventContext::TARGET],
        );
    }

    /**
     * @return array<string, array{SchemaViolationDisposition, string}>
     */
    public static function provideDispositions(): array
    {
        return [
            'rejected' => [SchemaViolationDisposition::Rejected, 'strict'],
            'relaxed by policy' => [SchemaViolationDisposition::RelaxedByPolicy, 'lenient'],
            'relaxed by control' => [SchemaViolationDisposition::RelaxedByControl, 'relaxed'],
        ];
    }

    public function test_record_schema_violations_emits_one_event_per_violation(): void
    {
        $violations = new SchemaViolations();
        $violations->record(
            new OperationException(
                'first',
                ResultCode::OBJECT_CLASS_VIOLATION,
            ),
            SchemaViolationDisposition::RelaxedByPolicy,
        );
        $violations->record(
            new OperationException(
                'second',
                ResultCode::CONSTRAINT_VIOLATION,
            ),
            SchemaViolationDisposition::RelaxedByPolicy,
        );

        $this->subject->recordSchemaViolations(
            $violations,
            self::wrap(new AddRequest(new Entry(
                new Dn(self::TARGET_DN),
                new Attribute('cn', 'Bob'),
            ))),
            $this->token,
        );

        self::assertCount(
            2,
            $this->recordingLogger->records,
        );
    }

    public function test_record_schema_violations_is_silent_when_empty(): void
    {
        $this->subject->recordSchemaViolations(
            new SchemaViolations(),
            self::wrap(new AddRequest(new Entry(
                new Dn(self::TARGET_DN),
                new Attribute('cn', 'Bob'),
            ))),
            $this->token,
        );

        self::assertSame(
            [],
            $this->recordingLogger->records,
        );
    }

    private static function wrap(RequestInterface $request): LdapMessageRequest
    {
        return new LdapMessageRequest(
            self::MESSAGE_ID,
            $request,
        );
    }

    /**
     * @return array{level: string, message: string, context: array<string, mixed>}
     */
    private function onlyRecord(): array
    {
        self::assertCount(
            1,
            $this->recordingLogger->records,
            'Expected exactly one log record.',
        );

        return $this->recordingLogger->records[0];
    }
}
