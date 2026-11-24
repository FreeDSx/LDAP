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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdType;
use FreeDSx\Ldap\Server\Backend\Auth\SubjectDnCredentialMapper;
use FreeDSx\Socket\Tls\Certificate;
use OpenSSLCertificate;
use PHPUnit\Framework\TestCase;

final class SubjectDnCredentialMapperTest extends TestCase
{
    /**
     * Throwaway self-signed cert: openssl req -x509 -subj "/C=US/O=Acme/CN=foo".
     */
    private const COCN_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIDNTCCAh2gAwIBAgIUW3+8Qyj/TsLNxg/Pdob8sf+1ahMwDQYJKoZIhvcNAQEL
        BQAwKjELMAkGA1UEBhMCVVMxDTALBgNVBAoMBEFjbWUxDDAKBgNVBAMMA2ZvbzAe
        Fw0yNjA2MDcyMzAwNThaFw0yNjA2MDgyMzAwNThaMCoxCzAJBgNVBAYTAlVTMQ0w
        CwYDVQQKDARBY21lMQwwCgYDVQQDDANmb28wggEiMA0GCSqGSIb3DQEBAQUAA4IB
        DwAwggEKAoIBAQDpS41EGltCjOdAeb46+NOcmP8TfitevD0msXl4aVoilhZPcr17
        go4VDGVVovHb9Ji3YtPs56rmEp/YxRTjy6uNvu4Uig2g1Iis3JjAEcz0NjiZPs4E
        6NENAvk4Y6/HvjK50w3yokUuZCGXuZfnDlR9PUr584/IylM3F3rjlCu5Cr05Dx5a
        /ci70zD7gJx+qFCc7XEy97fRr4qOFtIPkC+WSub7Oow0az91I9zuulUkGhFWQbdQ
        agOB3tZwod2ODW5MCiFCkssh1mG5mL8mUAbUrMspdQIU9TC3TL7my38S2bK0utr2
        +593aANAvN5guf2FU+10DcFYIpF115lpVOOLAgMBAAGjUzBRMB0GA1UdDgQWBBRs
        QIbfOVWmdTjl5vMYM8nYSiNeGTAfBgNVHSMEGDAWgBRsQIbfOVWmdTjl5vMYM8nY
        SiNeGTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDeXWPNUuqd
        EeUJeeCRZoKECOaGeZWoQuAeR5QffVjaCo8hS6JMD22p12HDz86ztLtilxgm43Cm
        l6RBL6QHCsDD5fReG8j7a8qRGx40aARzr6Z0orhl1/+TAvqJ21q/3f/qrJT/DFTi
        k2sIE5nvoYYDqdEzh8TgnK0VIKF6YqzK0Ix0NutvTUuHtBDiwFY7D++HJYsdtIEh
        NlC3t0UcRFnz+qrN7xYGcry1IDUfVcVOKJ6ISquqfx9/wMiw92CFQtJ7onridIkt
        BLiKOmEoCGr4yeu7QTR/N+DTRnyAqSHflCfy5V+WhKq0htIdI2K7ktyn91kZGnmX
        WpavO+u42dau
        -----END CERTIFICATE-----
        PEM;

    /**
     * Throwaway self-signed cert: openssl req -x509 -subj "/DC=com/DC=example/CN=bar".
     */
    private const DC_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIDWTCCAkGgAwIBAgIULi/f0ddOMTGz2lCfRHhhnW0jgJAwDQYJKoZIhvcNAQEL
        BQAwPDETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2V4YW1w
        bGUxDDAKBgNVBAMMA2JhcjAeFw0yNjA2MDcyMzAwNThaFw0yNjA2MDgyMzAwNTha
        MDwxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxl
        MQwwCgYDVQQDDANiYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDB
        bzaeSLulCbgl7eqdBx/o5C11L0JScSv1NuDK3h+6QJ65tPHzEeIM/K5ZVzkw5HlP
        3rcaqYQtSAy5pYMUttoj7kzzKRGRg97d475qPFm9wtMbTTHfPzDOSuvbQdhzWcYT
        Upw3sgYhFG9GTUveAc5wp7KhaQLnCZDWbO+Gwt0UTEoO/nu4tfrxdUWh2uqoL2uH
        mVZ7J3mYeLQQV5H1T3FTbPM0lV66H0QZwnvCa8rZ8MKqoxDqgvP6C0l64ikcM0Rl
        MS187XKksHsgDdmC9Qs1k5l5X0Joy3GXzRHSzaz1p0b2v3n9Xb1oZE2KQuj729SC
        Pln/8Kmf9SuNbzKfdkmdAgMBAAGjUzBRMB0GA1UdDgQWBBSQy0YakBKMSST+VgLc
        jZHaib5L4DAfBgNVHSMEGDAWgBSQy0YakBKMSST+VgLcjZHaib5L4DAPBgNVHRMB
        Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC0K2XKK1sAvzHreL3ERpjGQ/lT
        gwU7/4QRgffoZqjppF7LwhqO5D1DNTj9bTiHnobQziZpZtIdj+7h9WsBfzI5RHVZ
        QGL3EwPnnbf6mNXCLbJ2jvqmkDGd+wg0v4Q9gta24f0Y8QS9QV2b8nCAN4sTEw9P
        XMudQ/ezXFsIDS92VXy+ZdGXJmgPN19Kg0F6mtWziV16dopmNQK1LDxWhIVWIhBW
        /Hwtd8gmwlovAVKCQRjvAmlS6Y6hbijcuUFUs7ux5ablyuZ8CfZ1yU9HDWy4yOrl
        hMHSm/4AkHj2D7Y9F0iRHUlNj/jeXe42OsG9HibTTPkFic7z0WAglfwxqIZd
        -----END CERTIFICATE-----
        PEM;

    /**
     * Throwaway self-signed cert whose CN is text that reads as escapes.
     */
    private const ESCAPE_LOOKALIKE_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIC9DCCAdygAwIBAgIUCdwUFTlrBgH/sokRt5uxpKI7DP0wDQYJKoZIhvcNAQEL
        BQAwGjEYMBYGA1UEAwwPXDYxXDY0XDZkXDY5XDZlMB4XDTI2MTEyNDAxMjMxOVoX
        DTI2MTEyNTAxMjMxOVowGjEYMBYGA1UEAwwPXDYxXDY0XDZkXDY5XDZlMIIBIjAN
        BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwwj4EevTSbhaAlWMvohrCXA0Ch99
        e9xtg2/rOeWRiTYqtstVIsLKTg3xDw9vG4WlSATcPN43eahwSfpY7rQV4dJ5kGvZ
        ejL7bXi1jEbro6W+TomP5iTqQiJoTky4Ce0WMCG2+5j9l7RBwXfksKYmpyrSEo1q
        uGlM+rkAQ17O2QbZL3faL+WwQQQAA5E1WkMenqX4vUy+Xnc2wufedKWoXkkYtPTZ
        hFmTrd92LUxjn4OpQ2KLmMEiksxf9DFOyDWxdG7f9tSdp81t0m/8rMnbPDc56jK9
        D8Cfkn0J87IZmB2G7MkZCO2A86OHPamovqOEkFK+DM0ToXNgJymy0Yq6kQIDAQAB
        ozIwMDAdBgNVHQ4EFgQUKfm0VYxlPSOiWkHe3RKHpnV+YoswDwYDVR0TAQH/BAUw
        AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAR5tJNVO7In5bLAzHmMJL1fD3qBdTWunr
        ARBakfUZv+wszwTnP5xchh8zK0+G5uLejQGIaPBbVRYaCpLBLGT/yBBZD6oLetDD
        csbOGUlUMA3VgJVfa1W58Htw2jml5V0zVSPrBVOa59Be7zsZUQVYAtr02feyhFOm
        gsKVef0R2/qrOj8IMRKyX1E3x/eOyxu+8pFrJdnvSmbYYdrKXzAlborZRZ444pQv
        2e0dv8x/ljC7sxT6plsFtrX72fUVeNLvs/tmlo311wrTnYl9jyrvIkHgLPktH/0c
        Kc6pXWX5L+cYSveR9Wx5xt1JguPyxOTyhpMSs084RGRLuZCWl8Xpew==
        -----END CERTIFICATE-----
        PEM;

    public function test_it_reverses_the_subject_into_an_ldap_dn(): void
    {
        $authzId = (new SubjectDnCredentialMapper())->map($this->certificate(self::COCN_PEM));

        self::assertNotNull($authzId);
        self::assertTrue($authzId->isType(AuthzIdType::Dn));
        self::assertSame(
            (new Dn('cn=foo,o=acme,c=us'))->normalizedString(),
            (new Dn($authzId->getValue()))->normalizedString(),
        );
    }

    public function test_it_expands_multi_valued_components_like_dc(): void
    {
        $authzId = (new SubjectDnCredentialMapper())->map($this->certificate(self::DC_PEM));

        self::assertNotNull($authzId);
        self::assertSame(
            (new Dn('cn=bar,dc=example,dc=com'))->normalizedString(),
            (new Dn($authzId->getValue()))->normalizedString(),
        );
    }

    public function test_a_subject_value_that_reads_as_an_escape_keeps_its_literal_text(): void
    {
        $authzId = (new SubjectDnCredentialMapper())->map($this->certificate(self::ESCAPE_LOOKALIKE_PEM));

        self::assertNotNull($authzId);
        self::assertSame(
            'CN=\5c61\5c64\5c6d\5c69\5c6e',
            $authzId->getValue(),
        );
        self::assertNotSame(
            (new Dn('cn=admin'))->normalizedString(),
            (new Dn($authzId->getValue()))->normalizedString(),
        );
    }

    private function certificate(string $pem): Certificate
    {
        $x509 = openssl_x509_read($pem);
        if (!$x509 instanceof OpenSSLCertificate) {
            self::fail('Failed to read the fixture certificate.');
        }

        $certificate = Certificate::fromX509($x509);
        if ($certificate === null) {
            self::fail('Failed to parse the fixture certificate.');
        }

        return $certificate;
    }
}
