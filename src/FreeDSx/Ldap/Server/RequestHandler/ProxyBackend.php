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

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Write\WritableBackendTrait;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use Generator;
use SensitiveParameter;

/**
 * Proxies requests to an upstream LDAP server.
 *
 * Extend this class and provide the LdapClient via the constructor or by
 * overriding the ldap() method to customise connection options.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ProxyBackend implements WritableLdapBackendInterface, PasswordAuthenticatableInterface
{
    use WritableBackendTrait;

    protected ?LdapClient $ldap = null;

    protected ClientOptions $options;

    public function __construct(
        LdapClient|ClientOptions $clientOrOptions = new ClientOptions(),
    ) {
        if ($clientOrOptions instanceof LdapClient) {
            $this->ldap = $clientOrOptions;
            $this->options = new ClientOptions();
        } else {
            $this->options = $clientOrOptions;
        }
    }

    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
    ): EntryStream {
        return new EntryStream(
            $this->yieldSearchResults($request, $controls),
            isPreFiltered: true,
        );
    }

    /**
     * @return Generator<Entry>
     */
    private function yieldSearchResults(
        SearchRequest $request,
        ControlBag $controls,
    ): Generator {
        $entries = $this->ldap()->search(
            $request,
            ...$controls->toArray(),
        );

        foreach ($entries as $entry) {
            yield $entry;
        }
    }

    public function get(Dn $dn): ?Entry
    {
        return $this->ldap()->read($dn->toString());
    }

    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool {
        return $this->ldap()->compare(
            $dn,
            $filter->getAttribute(),
            $filter->getValue(),
        );
    }

    public function verifyPassword(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): bool {
        try {
            return (bool) $this->ldap()->bind($name, $password);
        } catch (BindException $e) {
            throw new OperationException(
                $e->getMessage(),
                $e->getCode(),
            );
        }
    }

    public function getPassword(string $username, string $mechanism): ?string
    {
        return null;
    }

    public function add(AddCommand $command): void
    {
        $this->ldap()->sendAndReceive(Operations::add($command->entry));
    }

    public function delete(DeleteCommand $command): void
    {
        $this->ldap()->sendAndReceive(Operations::delete($command->dn->toString()));
    }

    public function update(UpdateCommand $command): void
    {
        $this->ldap()->sendAndReceive(new ModifyRequest(
            $command->dn->toString(),
            ...$command->changes,
        ));
    }

    public function move(MoveCommand $command): void
    {
        $this->ldap()->sendAndReceive(new ModifyDnRequest(
            dn: $command->dn->toString(),
            newRdn: $command->newRdn->toString(),
            deleteOldRdn: $command->deleteOldRdn,
            newParentDn: $command->newParent?->toString(),
        ));
    }

    public function setLdapClient(LdapClient $client): void
    {
        $this->ldap = $client;
    }

    protected function ldap(): LdapClient
    {
        if ($this->ldap === null) {
            $this->ldap = new LdapClient($this->options);
        }

        return $this->ldap;
    }

}
