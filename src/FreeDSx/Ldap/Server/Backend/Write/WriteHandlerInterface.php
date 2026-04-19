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
 * Handles one or more LDAP write operations; the framework only calls handle() after supports() returns true.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WriteHandlerInterface
{
    public function supports(WriteRequestInterface $request): bool;

    public function handle(WriteRequestInterface $request): void;
}
