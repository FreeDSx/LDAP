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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\LdapClient;
use WeakReference;

class RootDseLoader
{
    private const ROOTDSE_ATTRIBUTES = [
        'supportedSaslMechanisms',
        'supportedControl',
        'supportedLDAPVersion',
    ];

    private ?Entry $rootDse = null;

    /**
     * @var WeakReference<LdapClient>
     */
    private readonly WeakReference $client;

    /**
     * The client is held weakly to break the cycle through the client that holds this loader.
     */
    public function __construct(LdapClient $client)
    {
        $this->client = WeakReference::create($client);
    }

    /**
     * Make a single search request to fetch the RootDSE. Handle the various errors that could occur.
     *
     * @throws OperationException
     * @throws RuntimeException when the client that loads it is gone
     */
    public function load(bool $reload = false): Entry
    {
        if ($reload === false && $this->rootDse !== null) {
            return $this->rootDse;
        }
        $client = $this->client->get() ?? throw new RuntimeException('The client that loads the RootDSE is gone.');

        $this->rootDse = $client->read(
            entry: '',
            attributes: self::ROOTDSE_ATTRIBUTES,
        );
        if ($this->rootDse === null) {
            throw new OperationException('Expected a single entry for the RootDSE. None received.');
        }

        return $this->rootDse;
    }
}
