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

/**
 * The peer responded and ended the session with a notice of disconnection. This closes the connection but is not a
 * transport level failure.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class NoticeOfDisconnectException extends ConnectionException {}
