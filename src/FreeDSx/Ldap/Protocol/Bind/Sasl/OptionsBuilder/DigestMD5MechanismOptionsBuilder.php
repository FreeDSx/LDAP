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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\SaslUsernameExtractorInterface;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;

/**
 * Builds options for the DIGEST-MD5 SASL mechanism on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DigestMD5MechanismOptionsBuilder implements MechanismOptionsBuilderInterface
{
    use RequiresPasswordTrait;

    public function __construct(
        private readonly SaslHandlerInterface $handler,
        private readonly SaslUsernameExtractorInterface $usernameExtractor,
    ) {
    }

    /**
     * {@inheritDoc}
     *
     * @throws OperationException
     */
    public function buildOptions(
        ?string $received,
        string $mechanism)
    : array {
        if ($received === null) {
            return [];
        }

        $username = $this->usernameExtractor->extractUsername(DigestMD5Mechanism::NAME, $received);
        $password = $this->requirePassword($this->handler->getPassword($username, DigestMD5Mechanism::NAME));

        return ['password' => $password];
    }

    /**
     * {@inheritDoc}
     */
    public function supports(string $mechanism): bool
    {
        return $mechanism === DigestMD5Mechanism::NAME;
    }
}
