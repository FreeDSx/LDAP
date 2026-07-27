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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditSinkInterface;

/**
 * Central change-journal settings a storage backend builder assembles its journal from.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ChangeJournalConfig
{
    public function __construct(
        public ReplicaId $origin = new ReplicaId('local'),
        public RetentionPolicy $retention = new RetentionPolicy(),
        public ?AuditSinkInterface $auditSink = null,
    ) {}
}
