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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use PDO;

/**
 * Shared PdoStorage wiring: concrete factories provide dialect, translator, and connection opener; the trait picks the provider.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoStorageFactoryTrait
{
    abstract protected function dialect(): PdoDialectInterface;

    abstract protected function translator(): FilterTranslatorInterface;

    abstract protected function openConnection(PdoDialectInterface $dialect): PDO;

    public function create(): PdoStorage
    {
        return $this->createShared();
    }

    protected function createShared(): PdoStorage
    {
        $dialect = $this->dialect();
        $factory = fn (): PDO => $this->openConnection($dialect);

        return new PdoStorage(
            new SharedPdoConnectionProvider(
                $factory(),
                $factory,
            ),
            $this->translator(),
            $dialect,
        );
    }

    protected function createPerCoroutine(): PdoStorage
    {
        $dialect = $this->dialect();

        return new PdoStorage(
            new CoroutinePdoConnectionProvider(fn(): PDO => $this->openConnection($dialect)),
            $this->translator(),
            $dialect,
        );
    }
}
