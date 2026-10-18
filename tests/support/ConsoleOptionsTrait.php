<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use BackedEnum;
use Symfony\Component\Console\Input\InputInterface;

trait ConsoleOptionsTrait
{
    private function getStringOption(InputInterface $input, string $name): string
    {
        $value = $input->getOption($name);

        return is_string($value) ? $value : '';
    }

    /**
     * The values an enum-backed option accepts, as its help text and errors list them.
     *
     * @param list<BackedEnum> $cases
     */
    private static function enumChoices(array $cases): string
    {
        return implode(
            ' | ',
            array_map(
                static fn(BackedEnum $case): string => (string) $case->value,
                $cases,
            ),
        );
    }
}
