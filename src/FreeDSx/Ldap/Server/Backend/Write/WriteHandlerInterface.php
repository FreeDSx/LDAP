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

/**
 * Implemented by any class that handles one or more LDAP write operations.
 *
 * The framework calls supports() first and only calls handle() when it returns
 * true, so implementations never need no-op stubs for unsupported operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WriteHandlerInterface
{
    public function supports(WriteRequestInterface $request): bool;

    public function handle(WriteRequestInterface $request): void;
}
