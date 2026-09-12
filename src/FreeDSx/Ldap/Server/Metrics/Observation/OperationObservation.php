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

namespace FreeDSx\Ldap\Server\Metrics\Observation;

use FreeDSx\Ldap\Operation\OperationType;

/**
 * A single observed operation, with its low-cardinality metric dimensions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationObservation
{
    /**
     * @param int|null $resultCode The LDAP result code, or null for an operation the client is never answered on.
     * @param string|null $bindMethod The bind sub-type (anonymous/simple/sasl) for binds, null otherwise.
     * @param string|null $searchScope The search scope (base/one/sub) for searches, null otherwise.
     */
    public function __construct(
        public OperationType $operation,
        public bool $succeeded,
        public float $durationSeconds,
        public ?int $resultCode,
        public ?string $bindMethod = null,
        public ?string $searchScope = null,
    ) {}
}
