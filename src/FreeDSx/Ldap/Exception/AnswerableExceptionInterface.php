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

namespace FreeDSx\Ldap\Exception;

use Throwable;

/**
 * A failure the server answers with a result code.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AnswerableExceptionInterface extends Throwable
{
    /**
     * What the client is told, which is not always the message the cause carries for the log.
     */
    public function getDiagnostic(): string;
}
