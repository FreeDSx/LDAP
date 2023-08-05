<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;

class RootDseLoader
{
    private const ROOTDSE_ATTRIBUTES = [
        'supportedSaslMechanisms',
        'supportedControl',
        'supportedLDAPVersion',
    ];

    private ?Entry $rootDse = null;

    public function __construct(private readonly LdapClient $client)
    {
    }

    /**
     * Make a single search request to fetch the RootDSE. Handle the various errors that could occur.
     *
     * @throws OperationException
     */
    public function load(bool $reload = false): Entry
    {
        if ($reload === false && $this->rootDse !== null) {
            return $this->rootDse;
        }
        $this->rootDse = $this->client->read(
            entry: '',
            attributes: self::ROOTDSE_ATTRIBUTES,
        );
        if ($this->rootDse === null) {
            throw new OperationException('Expected a single entry for the RootDSE. None received.');
        }

        return $this->rootDse;
    }
}
