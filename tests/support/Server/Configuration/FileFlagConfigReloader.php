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

namespace Tests\Support\FreeDSx\Ldap\Server\Configuration;

use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\ServerOptions;
use RuntimeException;

/**
 * Reloads from a flag file: "allow-anonymous" enables anonymous bind, "deny-sn" withholds sn, and "invalid" fails.
 *
 * "deny-sn-parent-only" withholds sn in the process that built the reloader and fails in any process forked from it.
 */
final readonly class FileFlagConfigReloader implements ConfigReloaderInterface
{
    private int $ownerPid;

    public function __construct(private string $flagFile)
    {
        $this->ownerPid = (int) getmypid();
    }

    public function reload(ServerOptions $current): ServerOptions
    {
        $flag = is_file($this->flagFile)
            ? trim((string) file_get_contents($this->flagFile))
            : '';

        if ($flag === 'invalid' || ($flag === 'deny-sn-parent-only' && getmypid() !== $this->ownerPid)) {
            throw new RuntimeException('The configuration flag file is invalid.');
        }

        fwrite(STDOUT, 'configuration reloaded...' . PHP_EOL);
        $reloaded = (clone $current)->setAllowAnonymous($flag === 'allow-anonymous');

        if ($flag !== 'deny-sn' && $flag !== 'deny-sn-parent-only') {
            return $reloaded;
        }

        return $reloaded->setAclRules($current->getAclRules()->prependAttributeRules(
            AttributeRule::deny(
                Subject::anyone(),
                new AnyTargetMatcher(),
                'sn',
            )->forRead(),
        ));
    }
}
