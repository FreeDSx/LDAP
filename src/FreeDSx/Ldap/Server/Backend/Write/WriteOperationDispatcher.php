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

use Closure;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;

/**
 * Hands a write command to the operation that performs it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class WriteOperationDispatcher implements WriteHandlerInterface
{
    /**
     * @param array<class-string<WriteRequestInterface>, Closure> $operations Keyed by the command each performs.
     */
    public function __construct(private array $operations) {}

    /**
     * @throws OperationException
     */
    public function handle(
        WriteRequestInterface $request,
        WriteContext $context,
    ): void {
        $operation = $this->operations[$request::class] ?? throw new OperationException(
            'This operation is not supported.',
            ResultCode::UNWILLING_TO_PERFORM,
        );

        $operation(
            $request,
            $context,
        );
    }
}
