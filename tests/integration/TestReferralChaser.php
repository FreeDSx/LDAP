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

namespace Tests\Integration\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\ReferralChaserInterface;

final class TestReferralChaser implements ReferralChaserInterface
{
    public function __construct(
        private readonly string $username,
        private readonly string $password,
    ) {
    }

    public function chase(
        LdapMessageRequest $request,
        LdapUrl $referral,
        ?BindRequest $bind,
    ): BindRequest {
        return new SimpleBindRequest(
            $this->username,
            $this->password
        );
    }

    public function client(ClientOptions $options): LdapClient
    {
        return new LdapClient($options);
    }
}
