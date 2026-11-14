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

namespace FreeDSx\Ldap\Server\Initialization\Requirement;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;

use function sprintf;

/**
 * A manager password must be one a bind could verify.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ManagerPasswordRequirement implements RequirementInterface
{
    public function __construct(
        private ?ManagerIdentity $manager,
        private PasswordHashService $hashService,
    ) {}

    public function assertMet(): void
    {
        if ($this->manager === null) {
            return;
        }

        try {
            $this->hashService->assertVerifiable($this->manager->hashedPassword());
        } catch (InvalidArgumentException $e) {
            throw new RuntimeException(
                sprintf(
                    'The manager password can never be verified. %s',
                    $e->getMessage(),
                ),
                previous: $e,
            );
        }
    }
}
