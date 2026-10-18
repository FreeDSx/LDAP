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

namespace Tests\Performance\FreeDSx\Ldap;

use InvalidArgumentException;
use Tests\Performance\FreeDSx\Ldap\Config\DirectorySettings;
use Tests\Performance\FreeDSx\Ldap\Config\OutputFormat;
use Tests\Performance\FreeDSx\Ldap\Config\RunSettings;
use Tests\Performance\FreeDSx\Ldap\Config\SearchSettings;
use Tests\Performance\FreeDSx\Ldap\Config\SeedSettings;
use Tests\Performance\FreeDSx\Ldap\Config\ServerSettings;
use Tests\Performance\FreeDSx\Ldap\Workload\WorkloadMix;

/**
 * Immutable configuration for the load-test driver, one part per concern, each validating its own settings.
 */
final readonly class Config
{
    public function __construct(
        public ServerSettings $server,
        public RunSettings $run = new RunSettings(),
        public SeedSettings $seed = new SeedSettings(),
        public DirectorySettings $directory = new DirectorySettings(),
        public SearchSettings $search = new SearchSettings(),
        public OutputFormat $output = OutputFormat::Text,
    ) {
        $this->assertGroupsSeeded();
    }

    /**
     * Every class a serialized Config holds, for a reader that restricts what it unserializes.
     *
     * @return list<class-string>
     */
    public static function serializedClasses(): array
    {
        return [
            self::class,
            ServerSettings::class,
            RunSettings::class,
            SeedSettings::class,
            DirectorySettings::class,
            SearchSettings::class,
        ];
    }

    public function withRun(RunSettings $run): self
    {
        return new self(
            server: $this->server,
            run: $run,
            seed: $this->seed,
            directory: $this->directory,
            search: $this->search,
            output: $this->output,
        );
    }

    private function assertGroupsSeeded(): void
    {
        if (!(new WorkloadMix($this->run->mix))->drawsAny(WorkloadMix::GROUP_OPS)) {
            return;
        }

        if ($this->seed->groups < 1) {
            throw new InvalidArgumentException(sprintf(
                'The mix draws a group op. Set --seed-groups to at least 1. Group ops: %s.',
                implode(', ', WorkloadMix::GROUP_OPS),
            ));
        }

        // Members are drawn from the seeded entries the groups were not seeded holding.
        if ($this->seed->groupSize >= $this->seed->entries) {
            throw new InvalidArgumentException(
                '--seed-entries must exceed --seed-group-size, or no member is left to add.',
            );
        }
    }
}
