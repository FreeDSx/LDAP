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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkTarget;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Sync\Consumer\LinkedValueFilter;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class LinkedValueFilterTest extends TestCase
{
    private const GROUP_DN = 'cn=team,dc=example,dc=com';

    private const BOB = 'cn=bob,dc=example,dc=com';

    private RecordingLogger $logger;

    private LinkedValueFilter $subject;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->subject = new LinkedValueFilter(
            new LinkedAttributes(SchemaResource::Core->load()),
            $this->logger,
        );
    }

    public function test_an_entry_with_nothing_to_leave_out_is_returned_as_given(): void
    {
        $entry = $this->group(
            self::aliceWithUidOf(LinkTarget::MAX_UID_BITS),
            self::BOB,
        );

        self::assertSame(
            $entry,
            $this->subject->storable($entry),
        );
        self::assertSame(
            [],
            $this->logger->records,
        );
    }

    public function test_a_uid_longer_than_can_be_stored_is_left_out(): void
    {
        $filtered = $this->subject->storable($this->group(
            self::aliceWithUidOf(LinkTarget::MAX_UID_BITS + 1),
            self::BOB,
        ));

        self::assertSame(
            [self::BOB],
            $filtered->get('uniqueMember')?->getValues(),
        );
    }

    public function test_the_entry_given_keeps_the_value_left_out(): void
    {
        $entry = $this->group(
            self::aliceWithUidOf(LinkTarget::MAX_UID_BITS + 1),
            self::BOB,
        );

        $this->subject->storable($entry);

        self::assertCount(
            2,
            $entry->get('uniqueMember')?->getValues() ?? [],
        );
    }

    public function test_an_attribute_left_with_no_value_is_removed(): void
    {
        $filtered = $this->subject->storable($this->group(self::aliceWithUidOf(LinkTarget::MAX_UID_BITS + 1)));

        self::assertFalse($filtered->has('uniqueMember'));
    }

    public function test_leaving_a_value_out_logs_a_warning_naming_the_entry_and_attribute(): void
    {
        $this->subject->storable($this->group(
            self::aliceWithUidOf(LinkTarget::MAX_UID_BITS + 1),
            self::BOB,
        ));

        self::assertSame(
            [
                [
                    'level' => LogLevel::WARNING,
                    'message' => 'A replicated value carries a uid longer than can be stored and was left out.',
                    'context' => [
                        'dn' => self::GROUP_DN,
                        'attribute' => 'uniqueMember',
                    ],
                ],
            ],
            $this->logger->records,
        );
    }

    private function group(string ...$uniqueMembers): Entry
    {
        return new Entry(
            self::GROUP_DN,
            new Attribute(
                'cn',
                'team',
            ),
            new Attribute(
                'uniqueMember',
                ...$uniqueMembers,
            ),
        );
    }

    private static function aliceWithUidOf(int $bits): string
    {
        return "cn=alice,dc=example,dc=com#'" . str_repeat(
            '1',
            $bits,
        ) . "'B";
    }
}
