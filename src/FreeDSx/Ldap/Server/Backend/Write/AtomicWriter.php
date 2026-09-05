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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryAlreadyExistsException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use Throwable;

/**
 * Runs a write under the storage transaction and answers storage-layer failures with an LDAP result code.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AtomicWriter
{
    public function __construct(private EntryStorageInterface $storage) {}

    /**
     * @param callable(): void $operation
     * @throws OperationException
     * @throws InvalidDnSyntaxException
     */
    public function write(callable $operation): void
    {
        try {
            $this->storage->atomic($operation);
        } catch (OperationException|InvalidDnSyntaxException $e) {
            // Already answerable: one carries its own result code, the other is mapped on the way out.
            throw $e;
        } catch (EntryAlreadyExistsException $e) {
            throw new OperationException(
                $e->getMessage(),
                ResultCode::ENTRY_ALREADY_EXISTS,
                $e,
            );
        } catch (DnTooLongException $e) {
            throw new OperationException(
                $e->getMessage(),
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e,
            );
        } catch (StorageIoException $e) {
            throw new OperationException(
                'The backend storage is currently unavailable.',
                ResultCode::UNAVAILABLE,
                $e,
            );
        } catch (Throwable $e) {
            // let's not end the client session for a storage issue (though the cause is not known).
            // just return a proper code.
            throw new OperationException(
                'The result could not be completed.',
                ResultCode::OTHER,
                $e,
            );
        }
    }
}
