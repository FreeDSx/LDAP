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

namespace FreeDSx\Ldap\Server\AccessControl\Read;

use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;

/**
 * Whether an attribute may be read wherever it is held, or only the entry holding it can say.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ReadVerdict
{
    case Allow;

    case Deny;

    case PerEntry;

    public static function fromEffect(Effect $effect): self
    {
        return $effect === Effect::Allow
            ? self::Allow
            : self::Deny;
    }
}
