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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;

use function rtrim;
use function sprintf;

/**
 * A record that seeding or a changelog replay refused.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RecordRefusedException extends OperationException
{
    /**
     * @param ?int $ldifLine The LDIF line the record begins on, or null when it was not read from LDIF.
     */
    public function __construct(
        AnswerableExceptionInterface $refusal,
        private readonly Dn $dn,
        private readonly ?int $ldifLine = null,
    ) {
        parent::__construct(
            self::describe(
                $refusal->getMessage(),
                $dn,
                $ldifLine,
            ),
            $refusal->getCode(),
            $refusal,
            $refusal instanceof OperationException
                ? $refusal->getMatchedDn()
                : null,
            $refusal instanceof OperationException
                ? $refusal->controls()
                : new ControlBag(),
        );
    }

    public function getDn(): Dn
    {
        return $this->dn;
    }

    /**
     * The LDIF line the record begins on, or null when it was not read from LDIF.
     */
    public function getLdifLine(): ?int
    {
        return $this->ldifLine;
    }

    private static function describe(
        string $reason,
        Dn $dn,
        ?int $line,
    ): string {
        $reason = rtrim(
            $reason,
            '.',
        );

        return $line === null
            ? sprintf(
                '%s (entry "%s").',
                $reason,
                $dn->toString(),
            )
            : sprintf(
                '%s (entry "%s", LDIF line %d).',
                $reason,
                $dn->toString(),
                $line,
            );
    }
}
