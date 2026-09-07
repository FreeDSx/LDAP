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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoJournalDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Utility\Uuid;

/**
 * The identity of the data a journal was built over.
 *
 * Minted once per database and read back thereafter.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PdoJournalGeneration
{
    private ?string $value = null;

    public function __construct(
        private readonly PdoJournalDialectInterface $dialect,
        private readonly PdoStatementPool $statements,
    ) {}

    public function value(): string
    {
        return $this->value ??= $this->readOrMint();
    }

    private function readOrMint(): string
    {
        $existing = $this->read();
        if ($existing !== '') {
            return $existing;
        }

        $this->statements->execute(
            $this->dialect->queryJournalGenerationClaim(),
            [Uuid::v4()],
        );

        // Re-read rather than trusting the value just written, since a concurrent minter may have claimed it first.
        return $this->read();
    }

    private function read(): string
    {
        return $this->statements
            ->execute($this->dialect->queryJournalGenerationRead())
            ->fetchStringColumn() ?? '';
    }
}
