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

use FreeDSx\Ldap\Exception\OperationException;

/**
 * Applies whichever LDAP write a command describes, or refuses one it has no operation for.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WriteHandlerInterface
{
    /**
     * @throws OperationException
     */
    public function handle(
        WriteRequestInterface $request,
        WriteContext $context,
    ): void;
}
