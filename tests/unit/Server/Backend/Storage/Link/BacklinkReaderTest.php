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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Link;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\BacklinkReader;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class BacklinkReaderTest extends TestCase
{
    use ServerContainerTrait;

    private const ALICE = 'cn=Alice,dc=foo,dc=bar';

    private const ADMINS = 'cn=Admins,dc=foo,dc=bar';

    private ReadEntryInterface&MockObject $storage;

    private BacklinkReader $subject;

    private Entry $entry;

    protected function setUp(): void
    {
        $this->storage = $this->createMock(ReadEntryInterface::class);
        $this->subject = new BacklinkReader(
            $this->storage,
            $this->fromContainer(LinkedAttributes::class)->backlinks(),
            25,
        );
        $this->entry = Entry::fromArray(
            self::ALICE,
            ['cn' => ['Alice']],
        );
    }

    public function test_it_reads_the_back_links_a_selection_names_under_the_link_cap(): void
    {
        $this->storage
            ->expects(self::once())
            ->method('find')
            ->with(
                self::callback(static fn(Dn $dn): bool => $dn->toString() === self::ALICE),
                self::callback(static fn(EntryProjection $projection): bool => $projection->backlinks === ['memberof']
                    && $projection->linkCap === 25),
            )
            ->willReturn(Entry::fromArray(
                self::ALICE,
                [
                    'cn' => ['Stored'],
                    'memberOf' => [self::ADMINS],
                ],
            ));

        $entry = $this->subject->withSelected(
            $this->entry,
            [new Attribute('memberOf')],
        );

        self::assertSame(
            [['Alice'], [self::ADMINS]],
            [
                $entry->get('cn')?->getValues(),
                $entry->get('memberOf')?->getValues(),
            ],
        );
    }

    public function test_it_reads_every_back_link_under_the_operational_wildcard(): void
    {
        $this->storage
            ->expects(self::once())
            ->method('find')
            ->with(
                self::anything(),
                self::callback(static fn(EntryProjection $projection): bool => $projection->backlinks === ['memberof']),
            )
            ->willReturn(Entry::fromArray(
                self::ALICE,
                ['memberOf' => [self::ADMINS]],
            ));

        self::assertSame(
            [self::ADMINS],
            $this->subject
                ->withSelected(
                    $this->entry,
                    [new Attribute('+')],
                )
                ->get('memberOf')
                ?->getValues(),
        );
    }

    public function test_it_keeps_a_back_link_cut_to_the_cap_under_its_range(): void
    {
        $this->storage
            ->method('find')
            ->willReturn(Entry::fromArray(
                self::ALICE,
                ['memberOf;range=0-24' => [self::ADMINS]],
            ));

        self::assertSame(
            [self::ADMINS],
            $this->subject
                ->withSelected(
                    $this->entry,
                    [new Attribute('memberOf')],
                )
                ->get(
                    'memberOf;range=0-24',
                    true,
                )
                ?->getValues(),
        );
    }

    public function test_it_reads_nothing_for_a_selection_naming_no_back_link(): void
    {
        $this->storage
            ->expects(self::never())
            ->method('find');

        self::assertNull($this->subject
            ->withSelected(
                $this->entry,
                [
                    new Attribute('cn'),
                    new Attribute('*'),
                ],
            )
            ->get('memberOf'));
    }

    public function test_an_entry_no_longer_stored_gains_no_back_link(): void
    {
        $this->storage
            ->method('find')
            ->willReturn(null);

        self::assertNull($this->subject
            ->withSelected(
                $this->entry,
                [new Attribute('memberOf')],
            )
            ->get('memberOf'));
    }
}
