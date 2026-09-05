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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryAlreadyExistsException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Write\AtomicWriter;
use PDOException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Throwable;
use TypeError;

final class AtomicWriterTest extends TestCase
{
    private EntryStorageInterface&MockObject $storage;

    private AtomicWriter $writer;

    protected function setUp(): void
    {
        $this->storage = $this->createMock(EntryStorageInterface::class);
        $this->writer = new AtomicWriter($this->storage);
    }

    public function test_it_runs_the_operation_inside_the_storage_transaction(): void
    {
        $ran = false;

        $this->storage
            ->expects($this->once())
            ->method('atomic')
            ->willReturnCallback(static fn(callable $operation) => $operation());

        $this->writer->write(function () use (&$ran): void {
            $ran = true;
        });

        $this->assertTrue($ran);
    }

    public function test_it_answers_a_dn_length_failure_with_an_admin_limit(): void
    {
        $this->storageThrows(new DnTooLongException('DN length 3073 exceeds the limit.'));

        try {
            $this->writer->write(static fn() => null);
            $this->fail('An OperationException was expected.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
            $this->assertSame(
                'DN length 3073 exceeds the limit.',
                $e->getMessage(),
            );
        }
    }

    public function test_it_answers_a_taken_dn_with_entry_already_exists(): void
    {
        $this->storageThrows(new EntryAlreadyExistsException('Entry already exists: cn=taken,dc=foo,dc=bar'));

        try {
            $this->writer->write(static fn() => null);
            $this->fail('An OperationException was expected.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::ENTRY_ALREADY_EXISTS,
                $e->getCode(),
            );
            $this->assertSame(
                'Entry already exists: cn=taken,dc=foo,dc=bar',
                $e->getMessage(),
            );
        }
    }

    public function test_it_answers_an_io_failure_with_unavailable(): void
    {
        $this->storageThrows(new StorageIoException('gone'));

        try {
            $this->writer->write(static fn() => null);
            $this->fail('An OperationException was expected.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
        }
    }

    public function test_it_answers_an_unclassified_storage_failure_with_a_result_code(): void
    {
        $cause = new PDOException('SQLSTATE[23000]: Duplicate entry for key uq_lc_dn');
        $this->storageThrows($cause);

        try {
            $this->writer->write(static fn() => null);
            $this->fail('An OperationException was expected.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::OTHER,
                $e->getCode(),
            );
            $this->assertSame(
                $cause,
                $e->getPrevious(),
            );
        }
    }

    public function test_it_keeps_the_driver_message_off_the_client_facing_diagnostic(): void
    {
        $this->storageThrows(new PDOException("Duplicate entry 'cn=secret,dc=foo,dc=bar' for key uq_lc_dn"));

        try {
            $this->writer->write(static fn() => null);
            $this->fail('An OperationException was expected.');
        } catch (OperationException $e) {
            $this->assertStringNotContainsString(
                'cn=secret',
                $e->getMessage(),
            );
        }
    }

    public function test_it_answers_an_engine_error_rather_than_letting_it_end_the_session(): void
    {
        $this->storageThrows(new TypeError('boom'));

        try {
            $this->writer->write(static fn() => null);
            $this->fail('An OperationException was expected.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::OTHER,
                $e->getCode(),
            );
        }
    }

    public function test_it_passes_an_operation_exception_through_untouched(): void
    {
        $thrown = new OperationException(
            'Access denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );
        $this->storageThrows($thrown);

        try {
            $this->writer->write(static fn() => null);
            $this->fail('An OperationException was expected.');
        } catch (OperationException $e) {
            $this->assertSame(
                $thrown,
                $e,
            );
        }
    }

    public function test_it_passes_an_invalid_dn_syntax_failure_through_untouched(): void
    {
        $thrown = new InvalidDnSyntaxException('bad dn');
        $this->storageThrows($thrown);

        $this->expectExceptionObject($thrown);

        $this->writer->write(static fn() => null);
    }

    private function storageThrows(Throwable $exception): void
    {
        $this->storage
            ->method('atomic')
            ->willThrowException($exception);
    }
}
