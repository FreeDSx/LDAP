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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Sasl\Mechanism\PlainMechanism;

/**
 * Builds options for the PLAIN SASL mechanism on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PlainMechanismOptionsBuilder implements MechanismOptionsBuilderInterface
{
    public function __construct(private readonly RequestHandlerInterface $dispatcher)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function buildOptions(
        ?string $received,
        string $mechanism,
    ): array {
        return [
            'validate' => fn (?string $authzId, string $authcId, string $password): bool =>
                $this->dispatcher->bind($authcId, $password),
        ];
    }

    public function supports(string $mechanism): bool
    {
        return $mechanism === PlainMechanism::NAME;
    }
}
