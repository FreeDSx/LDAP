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

namespace FreeDSx\Ldap\Server\Initialization;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Logging\EventLogger;

/**
 * Prepares the server to start with its configuration, or to adopt a reloaded one.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerInitialization
{
    /**
     * @param list<RequirementInterface> $requirements
     * @param list<AdvisoryInterface> $advisories
     */
    public function __construct(
        private array $requirements,
        private array $advisories,
        private EventLogger $events,
    ) {}

    /**
     * Refuses a configuration the server cannot run with, then records what it should warn about, before it starts.
     *
     * @throws RuntimeException
     */
    public function start(): void
    {
        $this->assertRequirementsMet();

        foreach ($this->advisories as $advisory) {
            foreach ($advisory->warnings() as $warning) {
                $this->events->record(
                    $warning->event,
                    $warning->context,
                );
            }
        }
    }

    /**
     * Refuses a reloaded configuration the server would refuse to start with.
     *
     * @throws RuntimeException
     */
    public function reload(): void
    {
        $this->assertRequirementsMet();
    }

    /**
     * @throws RuntimeException
     */
    private function assertRequirementsMet(): void
    {
        foreach ($this->requirements as $requirement) {
            $requirement->assertMet();
        }
    }
}
