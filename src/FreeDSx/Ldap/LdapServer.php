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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Ldif\LdifChangeRecord;
use FreeDSx\Ldap\Ldif\LdifParser;
use FreeDSx\Ldap\Ldif\Url\LdifUrlResolverInterface;
use FreeDSx\Ldap\Ldif\Url\RefusingUrlResolver;
use FreeDSx\Ldap\Ldif\Loader\LdifLoaderInterface;
use FreeDSx\Ldap\Ldif\Output\LdifOutputInterface;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\EntryIndexReindexer;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DirectoryDumper;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Storage\SeedOptions;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestReplayer;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use Generator;

/**
 * The LDAP server.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapServer
{
    private Container $container;

    public function __construct(
        private readonly ServerOptions $options,
        ?Container $container = null,
    ) {
        $this->container = $container ?? Container::forServer($this->options);
    }

    /**
     * Runs the LDAP server. Binds the socket and starts accepting client connections.
     *
     * @throws ConnectionException
     */
    public function run(): void
    {
        $runner = $this->options->getServerRunner() ?? $this->container->get(ServerRunnerInterface::class);

        $runner->run();
    }

    /**
     * Get the options currently set for the LDAP server.
     */
    public function getOptions(): ServerOptions
    {
        return $this->options;
    }

    /**
     * Bulk-loads LDIF content records into the configured storage as one atomic batch.
     *
     * Use {@see applyChanges()} instead to replay a changelog (modify/delete/rename) through the live write path.
     *
     * @throws LdifParseException when the LDIF cannot be parsed
     * @throws RuntimeException when the LDIF contains a non-add change record
     * @throws InvalidArgumentException when the creator DN is malformed or an entry's parent is missing
     * @throws OperationException when an entry violates the schema and validation mode is strict
     */
    public function seed(
        LdifLoaderInterface $loader,
        SeedOptions $options = new SeedOptions(),
    ): self {
        $this->container->get(LdapImporter::class)->importEntries(
            $this->streamSeedEntries($loader, $options->getUrlResolver()),
            $options->getCreatorDn(),
            $options->isIgnoreValidation(),
        );

        return $this;
    }

    /**
     * Replays an LDIF changelog against the configured backend via the live write path.
     *
     * Use {@see seed()} instead for bulk initial provisioning of content records straight to storage.
     *
     * @throws LdifParseException when the LDIF cannot be parsed
     * @throws OperationException when a write fails (no such entry, schema violation, etc.)
     */
    public function applyChanges(
        LdifLoaderInterface $loader,
        LdifUrlResolverInterface $urlResolver = new RefusingUrlResolver(),
    ): self {
        $this->container->get(WriteRequestReplayer::class)
            ->apply($this->streamChangeRequests($loader, $urlResolver));

        return $this;
    }

    /**
     * Streams the configured storage backend's entries as RFC 2849 LDIF content records to the given output.
     *
     * Symmetric with {@see seed()}: the produced LDIF re-seeds the directory verbatim, including operational
     * attributes.
     */
    public function dump(
        LdifOutputInterface $output,
        DumpOptions $options = new DumpOptions(),
    ): self {
        $output->write(
            $this->container->get(DirectoryDumper::class)->dump($options),
        );

        return $this;
    }

    /**
     * Rebuilds the configured backend's secondary indexes from the entries themselves.
     *
     * Needed after changing substring indexing or an attribute's matching rules, since both decide how a value is indexed.
     */
    public function reindex(): self
    {
        (new EntryIndexReindexer($this->container->get(EntryStorageInterface::class)))
            ->reindex();

        return $this;
    }

    /**
     * @return Generator<Entry>
     * @throws RuntimeException when the LDIF contains a non-add change record
     * @throws LdifParseException
     */
    private function streamSeedEntries(
        LdifLoaderInterface $loader,
        LdifUrlResolverInterface $urlResolver,
    ): Generator {
        foreach ($this->parseLdif($loader, $urlResolver) as $record) {
            if (!$record->request instanceof AddRequest) {
                throw new RuntimeException(
                    'seed() only accepts content records (adds). Use applyChanges() for modify/delete/rename.',
                );
            }

            yield $record->request->getEntry();
        }
    }

    /**
     * @return Generator<RequestInterface>
     * @throws LdifParseException
     */
    private function streamChangeRequests(
        LdifLoaderInterface $loader,
        LdifUrlResolverInterface $urlResolver,
    ): Generator {
        foreach ($this->parseLdif($loader, $urlResolver) as $record) {
            yield $record->request;
        }
    }

    /**
     * @return Generator<LdifChangeRecord>
     * @throws LdifParseException
     */
    private function parseLdif(
        LdifLoaderInterface $loader,
        LdifUrlResolverInterface $urlResolver,
    ): Generator {
        return $this->container->get(LdifParser::class)
            ->parse(
                $loader,
                $urlResolver,
            );
    }
}
