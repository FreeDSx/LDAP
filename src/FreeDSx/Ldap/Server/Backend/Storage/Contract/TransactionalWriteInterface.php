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

namespace FreeDSx\Ldap\Server\Backend\Storage\Contract;

use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;

/**
 * Groups a read-modify-write cycle into one unit of work.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface TransactionalWriteInterface
{
    /**
     * Execute $operation as an atomic read-modify-write cycle; implementations must hold an exclusive lock or transaction.
     *
     * @param callable(): void $operation Reads and writes issued from it join the transaction this opens.
     * @throws AnswerableExceptionInterface
     */
    public function atomic(callable $operation): void;
}
