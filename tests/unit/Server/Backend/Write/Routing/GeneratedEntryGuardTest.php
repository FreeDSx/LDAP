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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Routing;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\Routing\GeneratedEntryGuard;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\GeneratedEntry;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class GeneratedEntryGuardTest extends TestCase
{
    private GeneratedEntryGuard $subject;

    protected function setUp(): void
    {
        $this->subject = new GeneratedEntryGuard();
    }

    #[DataProvider('generatedEntryWriteProvider')]
    public function test_a_write_naming_a_generated_entry_is_refused_rather_than_reported_missing(
        RequestInterface $request,
    ): void {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->subject->assertWritable(
            $request,
            $this->context(),
        );
    }

    /**
     * @return iterable<string, array{RequestInterface}>
     */
    public static function generatedEntryWriteProvider(): iterable
    {
        foreach (GeneratedEntry::cases() as $entry) {
            yield "add the {$entry->name} entry" => [
                new AddRequest(Entry::create($entry->value)),
            ];
            yield "modify the {$entry->name} entry" => [
                new ModifyRequest($entry->value, Change::add('description', 'probe')),
            ];
            yield "delete the {$entry->name} entry" => [
                new DeleteRequest($entry->value),
            ];
        }

        // A respelling of a reserved name is the same name, which is what the normalizing compare is for.
        yield 'delete a respelled generated entry' => [
            new DeleteRequest('cn = subschema'),
        ];

        yield 'modify dn away from a generated entry' => [
            new ModifyDnRequest('cn=Subschema', 'cn=foo', true),
        ];
        // The name is taken wherever the rename would land it, not only where it starts.
        yield 'modify dn onto a generated entry' => [
            new ModifyDnRequest('cn=foo,dc=foo,dc=bar', 'cn=monitor', true, ''),
        ];
    }

    #[DataProvider('generatedParentProvider')]
    public function test_placing_an_entry_beneath_a_generated_entry_is_refused(RequestInterface $request): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->subject->assertWritable(
            $request,
            $this->context(),
        );
    }

    /**
     * @return iterable<string, array{RequestInterface}>
     */
    public static function generatedParentProvider(): iterable
    {
        foreach (GeneratedEntry::cases() as $entry) {
            yield "move beneath the {$entry->name} entry" => [
                new ModifyDnRequest('cn=foo,dc=foo,dc=bar', 'cn=foo', true, $entry->value),
            ];

            // A top level add names no parent at all, so the RootDSE can never be one.
            if ($entry === GeneratedEntry::RootDse) {
                continue;
            }

            yield "add beneath the {$entry->name} entry" => [
                new AddRequest(Entry::create("cn=child,{$entry->value}")),
            ];
        }
    }

    public function test_a_system_write_may_create_a_naming_context_beneath_the_root_dse(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertWritable(
            new ModifyDnRequest('cn=foo,dc=foo,dc=bar', 'cn=foo', true, ''),
            $this->systemContext(),
        );
    }

    public function test_an_add_at_the_top_level_is_left_to_the_placement_guard(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertWritable(
            new AddRequest(Entry::create('dc=new')),
            $this->context(),
        );
    }

    public function test_a_write_below_a_naming_context_is_not_refused(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertWritable(
            new DeleteRequest('cn=monitor,dc=foo,dc=bar'),
            $this->context(),
        );
    }

    private function context(): WriteContext
    {
        return new WriteContext(
            new AnonToken(),
            new ControlBag(),
        );
    }

    private function systemContext(): WriteContext
    {
        return WriteContext::system(
            new AnonToken(),
            new ControlBag(),
        );
    }
}
