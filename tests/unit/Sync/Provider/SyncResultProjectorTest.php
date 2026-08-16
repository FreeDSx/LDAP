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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Sync\Provider\SyncResultProjector;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class SyncResultProjectorTest extends TestCase
{
    private const UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private AccessControlInterface&MockObject $accessControl;

    private FilterEvaluatorInterface&MockObject $filterEvaluator;

    private TokenInterface&MockObject $token;

    private bool $hidden = false;

    private bool $filterMatches = true;

    private SyncResultProjector $subject;

    protected function setUp(): void
    {
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->filterEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->token = $this->createMock(TokenInterface::class);

        $this->accessControl
            ->method('isEntryVisible')
            ->willReturnCallback(fn(TokenInterface $token, Entry $entry): bool => !$this->hidden);
        $this->filterEvaluator
            ->method('evaluate')
            ->willReturnCallback(fn(): bool => $this->filterMatches);

        $this->subject = new SyncResultProjector(
            accessControl: $this->accessControl,
            filterEvaluator: $this->filterEvaluator,
            schema: SchemaResource::Core->load(),
        );
    }

    public function test_a_visible_searched_entry_becomes_an_add(): void
    {
        $result = $this->subject->projectSearched(
            $this->entry('cn=a,dc=example,dc=com', self::UUID),
            $this->request(),
            $this->token,
        );

        self::assertNotNull($result);
        self::assertSame(
            SyncStateControl::STATE_ADD,
            $result->control->getState(),
        );
        self::assertSame(
            self::UUID,
            $result->control->decodedUuid(),
        );
    }

    public function test_a_visible_entry_is_shipped_whole_including_sensitive_attributes(): void
    {
        $entry = Entry::create(
            'cn=a,dc=example,dc=com',
            [
                'cn' => 'x',
                'userPassword' => '{BCRYPT}$2y$10$abcdefghijklmnopqrstuv',
                'entryUUID' => self::UUID,
            ],
        );

        $result = $this->subject->projectSearched(
            $entry,
            $this->request(),
            $this->token,
        );

        self::assertNotNull($result);
        self::assertSame(
            '{BCRYPT}$2y$10$abcdefghijklmnopqrstuv',
            $result->entry->getEntry()->get('userPassword')?->firstValue(),
        );
    }

    public function test_a_searched_entry_is_limited_to_the_requested_attributes(): void
    {
        $result = $this->subject->projectSearched(
            Entry::create(
                'cn=a,dc=example,dc=com',
                [
                    'cn' => 'x',
                    'sn' => 'y',
                    'entryUUID' => self::UUID,
                ],
            ),
            $this->request('cn'),
            $this->token,
        );

        self::assertNotNull($result);
        self::assertSame(
            ['cn'],
            array_map(
                static fn(Attribute $attribute): string => $attribute->getDescription(),
                $result->entry->getEntry()->getAttributes(),
            ),
        );
        self::assertSame(
            self::UUID,
            $result->control->decodedUuid(),
        );
    }

    public function test_a_searched_entry_hidden_by_acl_is_null(): void
    {
        $this->hidden = true;

        self::assertNull($this->subject->projectSearched(
            $this->entry('cn=a,dc=example,dc=com', self::UUID),
            $this->request(),
            $this->token,
        ));
    }

    public function test_a_fetched_entry_that_leaves_the_filter_becomes_a_delete(): void
    {
        $this->filterMatches = false;

        $result = $this->subject->projectFetched(
            $this->entry('cn=a,dc=example,dc=com', self::UUID),
            $this->change(ChangeType::Modify),
            $this->request(),
            $this->token,
        );

        self::assertNotNull($result);
        self::assertSame(
            SyncStateControl::STATE_DELETE,
            $result->control->getState(),
        );
    }

    public function test_a_fetched_entry_hidden_by_acl_without_a_pre_image_is_null(): void
    {
        $this->hidden = true;

        self::assertNull($this->subject->projectFetched(
            $this->entry('cn=a,dc=example,dc=com', self::UUID),
            $this->change(ChangeType::Modify),
            $this->request(),
            $this->token,
        ));
    }

    public function test_a_fetched_modify_is_projected_as_a_modify(): void
    {
        $result = $this->subject->projectFetched(
            $this->entry('cn=a,dc=example,dc=com', self::UUID),
            $this->change(ChangeType::Modify),
            $this->request(),
            $this->token,
        );

        self::assertNotNull($result);
        self::assertSame(
            SyncStateControl::STATE_MODIFY,
            $result->control->getState(),
        );
    }

    public function test_a_fetched_add_is_projected_as_an_add(): void
    {
        $result = $this->subject->projectFetched(
            $this->entry('cn=a,dc=example,dc=com', self::UUID),
            $this->change(ChangeType::Add),
            $this->request(),
            $this->token,
        );

        self::assertNotNull($result);
        self::assertSame(
            SyncStateControl::STATE_ADD,
            $result->control->getState(),
        );
    }

    public function test_a_visible_delete_with_a_pre_image_becomes_a_delete(): void
    {
        $result = $this->subject->projectDeleted(
            $this->deleteChange($this->entry('cn=a,dc=example,dc=com', self::UUID)),
            $this->request(),
            $this->token,
        );

        self::assertNotNull($result);
        self::assertSame(
            SyncStateControl::STATE_DELETE,
            $result->control->getState(),
        );
    }

    public function test_a_delete_without_a_pre_image_is_null(): void
    {
        self::assertNull($this->subject->projectDeleted(
            $this->deleteChange(null),
            $this->request(),
            $this->token,
        ));
    }

    public function test_a_malformed_uuid_is_logged_and_skipped(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger
            ->expects($this->once())
            ->method('log')
            ->with(
                LogLevel::WARNING,
                ServerEvent::SyncEntrySkipped->value,
                self::callback(fn(array $context): bool => ($context['dn'] ?? null) === 'cn=a,dc=example,dc=com'),
            );

        $subject = new SyncResultProjector(
            accessControl: $this->accessControl,
            filterEvaluator: $this->filterEvaluator,
            schema: SchemaResource::Core->load(),
            eventLogger: new EventLogger($logger, EventLogPolicy::default()),
        );

        self::assertNull($subject->projectSearched(
            $this->entry('cn=a,dc=example,dc=com', 'not-a-uuid'),
            $this->request(),
            $this->token,
        ));
    }

    private function entry(
        string $dn,
        string $uuid,
    ): Entry {
        return Entry::create(
            $dn,
            [
                'cn' => 'x',
                'entryUUID' => $uuid,
            ],
        );
    }

    private function change(ChangeType $changeType): PendingChange
    {
        return new PendingChange(
            changeType: $changeType,
            dn: new Dn('cn=a,dc=example,dc=com'),
            entryUuid: self::UUID,
            authzId: AuthzId::anonymous(),
        );
    }

    private function deleteChange(?Entry $preImage): PendingChange
    {
        return new PendingChange(
            changeType: ChangeType::Delete,
            dn: new Dn('cn=a,dc=example,dc=com'),
            entryUuid: self::UUID,
            authzId: AuthzId::anonymous(),
            preImage: $preImage,
        );
    }

    private function request(string ...$attributes): SearchRequest
    {
        return (new SearchRequest(Filters::present('objectClass'), ...$attributes))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
    }
}
