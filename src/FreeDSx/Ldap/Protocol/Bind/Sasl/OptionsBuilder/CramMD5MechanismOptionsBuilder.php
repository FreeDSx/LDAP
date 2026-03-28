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

use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;

/**
 * Builds options for the CRAM-MD5 SASL mechanism on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CramMD5MechanismOptionsBuilder implements MechanismOptionsBuilderInterface
{
    use RequiresPasswordTrait;

    public function __construct(private readonly SaslHandlerInterface $handler)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function buildOptions(
        ?string $received,
        string $mechanism,
    ): array {
        if ($received === null) {
            return [];
        }

        return [
            'password' => function (string $username, string $challenge): string {
                $password = $this->requirePassword($this->handler->getPassword(
                    $username,
                    CramMD5Mechanism::NAME
                ));

                return hash_hmac(
                    'md5',
                    $challenge,
                    $password,
                );
            },
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function supports(string $mechanism): bool
    {
        return $mechanism === CramMD5Mechanism::NAME;
    }
}
