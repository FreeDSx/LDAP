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

use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use Throwable;

final class LdapClientReferralTest extends LdapTestCase
{
    private const REFERRAL_DN = 'ou=Referral-Test,ou=FreeDSx-Test,dc=example,dc=com';

    private const MULTI_REFERRAL_DN = 'ou=Multi-Referral-Test,ou=FreeDSx-Test,dc=example,dc=com';

    private const REFERRAL_CHAIN_DN = 'ou=Referral-Chain-Test,ou=FreeDSx-Test,dc=example,dc=com';

    private LdapClient $client;

    public function setUp(): void
    {
        $this->client = $this->getClient();
        $this->bindClient($this->client);
    }

    public function tearDown(): void
    {
        try {
            $this->client->unbind();
        } catch (Throwable) {
        }
    }

    public function test_it_throws_a_referral_exception_when_an_operation_targets_a_referral_entry(): void
    {
        $this->client = $this->getClient(
            $this->makeOptions()->setReferral(LdapClient::REFERRAL_THROW)
        );
        $this->bindClient($this->client);

        $this->expectException(ReferralException::class);

        $this->client->send(Operations::compare(self::REFERRAL_DN, 'ou', 'Referral-Test'));
    }

    public function test_it_ignores_a_referral_when_ignore_is_set(): void
    {
        $this->client = $this->getClient(
            $this->makeOptions()->setReferral(LdapClient::REFERRAL_IGNORE)
        );
        $this->bindClient($this->client);

        $result = $this->client->send(Operations::compare(
            self::REFERRAL_DN,
            'ou',
            'Referral-Test'
        ));

        self::assertNull($result);
    }

    public function test_it_follows_a_referral_to_the_target_server(): void
    {
        $chaser = new TestReferralChaser(
            username: (string) getenv('LDAP_USERNAME'),
            password: (string) getenv('LDAP_PASSWORD'),
        );

        $this->client = $this->getClient(
            $this->makeOptions()
                ->setReferral(LdapClient::REFERRAL_FOLLOW)
                ->setReferralChaser($chaser)
        );
        $this->bindClient($this->client);

        // The compare is re-sent to the referral target (ou=Accounting,...) on localhost.
        // Comparing ou=Accounting against value 'Accounting' should return TRUE (compare response code 6).
        $response = $this->client->send(Operations::compare(
            self::REFERRAL_DN,
            'ou',
            'Accounting'
        ));

        self::assertInstanceOf(
            CompareResponse::class,
            $response?->getResponse()
        );
        self::assertSame(
            ResultCode::COMPARE_TRUE,
            $response->getResponse()->getResultCode()
        );
    }

    public function test_it_falls_back_to_the_next_referral_on_connection_failure(): void
    {
        $chaser = new TestReferralChaser(
            username: (string) getenv('LDAP_USERNAME'),
            password: (string) getenv('LDAP_PASSWORD'),
        );

        $this->client = $this->getClient(
            $this->makeOptions()
                ->setReferral(LdapClient::REFERRAL_FOLLOW)
                ->setReferralChaser($chaser)
        );
        $this->bindClient($this->client);

        // First ref points to nonexistent.invalid (connection failure), second to localhost.
        // The handler must skip the failed URL and succeed via the second.
        $response = $this->client->send(Operations::compare(
            self::MULTI_REFERRAL_DN,
            'ou',
            'Accounting'
        ));

        self::assertInstanceOf(
            CompareResponse::class,
            $response?->getResponse()
        );
        self::assertSame(
            ResultCode::COMPARE_TRUE,
            $response->getResponse()->getResultCode()
        );
    }

    public function test_it_follows_a_chained_referral_to_the_final_target(): void
    {
        $chaser = new TestReferralChaser(
            username: (string) getenv('LDAP_USERNAME'),
            password: (string) getenv('LDAP_PASSWORD'),
        );

        $this->client = $this->getClient(
            $this->makeOptions()
                ->setReferral(LdapClient::REFERRAL_FOLLOW)
                ->setReferralChaser($chaser)
        );
        $this->bindClient($this->client);

        // Chain-Referral-Test → Referral-Test → Accounting.
        // Each hop creates a new client with the same options (REFERRAL_FOLLOW), so the
        // chain resolves transparently to the final compare on ou=Accounting.
        $response = $this->client->send(Operations::compare(
            self::REFERRAL_CHAIN_DN,
            'ou',
            'Accounting'
        ));

        self::assertInstanceOf(
            CompareResponse::class,
            $response?->getResponse()
        );
        self::assertSame(
            ResultCode::COMPARE_TRUE,
            $response->getResponse()->getResultCode()
        );
    }
}
