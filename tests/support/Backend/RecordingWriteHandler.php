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

namespace Tests\Support\FreeDSx\Ldap\Backend;

use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;

/**
 * Write handler that accepts every command and records each dispatch for inspection.
 */
final class RecordingWriteHandler implements WriteHandlerInterface
{
    /**
     * @var list<array{request: WriteRequestInterface, context: WriteContext}>
     */
    public array $dispatched = [];

    public function handle(
        WriteRequestInterface $request,
        WriteContext $context,
    ): void {
        $this->dispatched[] = [
            'request' => $request,
            'context' => $context,
        ];
    }
}
