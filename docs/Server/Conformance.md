Conformance
===========

* [Registered Identifiers](#registered-identifiers)
    * [Extended Operations](#extended-operations)
    * [Attribute Types](#attribute-types)
    * [Schema Extensions](#schema-extensions)
* [Deliberate Deviations](#deliberate-deviations)
    * [Group Membership Is Optional](#group-membership-is-optional)
    * [Hexstring RDN Values](#hexstring-rdn-values)
    * [DN Values Are Always Case-Folded](#dn-values-are-always-case-folded)
    * [Range Retrieval Options](#range-retrieval-options)
    * [Matching Without a Declared Rule](#matching-without-a-declared-rule)
    * [Aliases Are Not Dereferenced While Searching](#aliases-are-not-dereferenced-while-searching)
    * [Attribute-Less Extensible Match](#attribute-less-extensible-match)
    * [Unauthenticated Bind Rides on the Anonymous Switch](#unauthenticated-bind-rides-on-the-anonymous-switch)
    * [Value Modification of an Unreadable Attribute](#value-modification-of-an-unreadable-attribute)
    * [Paging and the Client Size Limit](#paging-and-the-client-size-limit)
    * [Password Policy on Compare](#password-policy-on-compare)
    * [Replication Sends Full Entries](#replication-sends-full-entries)
* [Not Implemented](#not-implemented)

This collects the identifiers the server defines for itself and the places where it departs
from the various RFCs.

# Registered Identifiers

FreeDSx holds IANA Private Enterprise Number 66207, which makes `1.3.6.1.4.1.66207` the arc for
anything we define. Everything else uses the OID assigned by the RFC or draft that defines
it.

```
1.3.6.1.4.1.66207        FreeDSx
                 .1      LDAP
                   .1    extended operations
                   .2    attribute types
```

## Extended Operations

| OID | Name | Purpose                                                                                           |
| --- | --- |---------------------------------------------------------------------------------------------------|
| `1.3.6.1.4.1.66207.1.1.1` | Password policy state forward | Lets a replica send the bind state it observed to the primary. See [Replication](Replication.md). |

## Attribute Types

| OID | Name | Purpose                                                                                                                                                                                                                                                   |
| --- | --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `1.3.6.1.4.1.66207.1.2.1` | `pwdMaxRecordedFailure` | How many failure timestamps `pwdFailureTime` retains. `draft-behera-ldap-password-policy-10` purges the list only by `pwdFailureCountInterval` and says nothing about retention. This closes a gap in the RFC. See [Password Policy](Password-Policy.md). |

## Schema Extensions

The following are FreeDSx specific schema extensions. 

| Extension | Purpose                                                                                                              |
| --- |----------------------------------------------------------------------------------------------------------------------|
| `X-CONFIDENTIAL` | Reading the attribute needs an explicit grant. Without one it is neither returned nor matched by a filter.           |
| `X-LINKED` | Values are DNs stored as rows in the link table rather than in the entry itself. This enforces referential integrity. |
| `X-LINKED-BY` | The attribute is the reverse of a linked attribute and is derived from it (as `memberOf` is derived from `member`.   |
| `X-MAX-VALUES` | How many values the attribute may hold. Zero lifts the cap. |

[Schema Validation](Schema.md) covers what each one changes in practice.

# Deliberate Deviations

## Group Membership Is Optional

RFC 4519 sections 3.5 and 3.6 put `member` in the MUST list of `groupOfNames` and `uniqueMember` in
the MUST list of `groupOfUniqueNames`. Taken literally a group cannot be created without members,
and removing the last member of a group is a schema violation.

The shipped schema sets both to MAY. This makes an empty group is an ordinary administrative state,
and helps linked attributes work without awkward workarounds.

## Hexstring RDN Values

RFC 4514 section 2.4 allows an attribute value in a DN to be written as `#` followed by the hex
encoding of its BER representation. The server refuses that form with an invalid DN syntax error.

Nothing is known to emit it, and a literal `#` at the start of a value can be written as `\23`
instead, which is what the server produces when it renders one.

## DN Values Are Always Case-Folded

RFC 4517 section 4.2.15 matches two DN components by the equality rule of their attribute type (such that a
`caseExactMatch` naming attribute should compare case-sensitively). One case-insensitive profile is
applied to every component instead.

Two entries whose DNs differ only in case would create distinct entries, and accidental case
differences are far likelier than deliberate ones. Every naming attribute in normal use is
case-insensitive already.

## Range Retrieval Options

RFC 4512 section 2.5 restricts an attribute option to a keystring, which cannot contain `=`. The
range retrieval convention uses `member;range=0-99`, which puts it at odds with the RFC. Range retrieval
is allowed as a way to paginate linked attributes and has existing usage (Active Directory, where this form originated).

Only a linked attribute or a back-link can be ranged A range on any other attribute is refused with
`unwillingToPerform`. See [Range Retrieval](../Client/Range-Retrieval.md) for the client side and [Schema Validation](Schema.md#how-many-values-a-read-returns) for how the window is decided.

## Matching Without a Declared Rule

RFC 4512 section 2.5.1 leaves a type with no EQUALITY or ORDERING rule in its `SUP` chain unmatchable,
and RFC 4511 section 4.5.1.7 makes such an assertion Undefined. RFC 4519 itself defines many core
types that way. Rather than make those unmatchable, equality falls back to a case-insensitive comparison and ordering
to the server's own order.

## Aliases Are Not Dereferenced While Searching

RFC 4511 section 4.5.1.3 has an alias found within a search's scope replaced by the entry. An
alias met while searching is returned as the ordinary entry it is, so `derefInSearching` and the
searching half of `derefAlways` are accepted and then not acted on.

Dereferencing a search base is implemented. And dangling or looping alias' answers
`aliasProblem`.

## Attribute-Less Extensible Match

RFC 4511 section 4.5.1.7.7 has an extensible match that names a matching rule but no attribute type
assert against every attribute supporting that rule. It is refused with `inappropriateMatching`.

An assertion with no attribute cannot be weighed against the ACL and is not safe to use.

## Unauthenticated Bind Rides and the Anonymous Switch

RFC 4513 section 5.1.2 treats a non-empty DN with an empty password as its own mechanism and says
servers SHOULD fail it by default. The default does fail it, since anonymous access is off by default.

What cannot be expressed is refusing an unauthenticated bind while permitting an anonymous one. The DN is inert
for authorization either way and the only real server difference is what's recorded in the audit log.

## Value Modification of an Unreadable Attribute

RFC 4511 section 4.6 answers a modify `add` of a present value with `attributeOrValueExists` and a
`delete` of an absent one with `noSuchAttribute`. Both codes report on matched stored values.

A value-level `add` or `delete` against an unreadable attribute is refused with
`insufficientAccessRights`, which makes those two codes unreachable in that context. A
`replace` is unaffected, since it's an unconditional write.

## Paging and the Client Size Limit

RFC 2696 section 3 says a server SHOULD ignore the paging control when the page size is at least the
client's size limit. `sizeLimit` defaults to 0 meaning unlimited, so applying that literally would
disable paging for every client that sets none.

The size limit bounds each page rather than the whole paged operation. RFC 2696 never states which.

## Password Policy on Compare

Section 8.1 of `draft-behera-ldap-password-policy-10` counts a failed Compare against the password
attribute toward the failure counter.

However, `userPassword` is confidential in the schema. Comparing it is denied and nothing reaches the policy. This is
also the only place the draft asks for policy on something that is not a bind.

## Replication Sends Full Entries

RFC 3672 section 3 keeps subentries out of a subtree search that carries no subentries control, and a
replication search is a subtree search. They are included anyway, since a replica that cannot see them
cannot reproduce the administrative model it is replicating.

Confidential attributes are always replicated too. Only the entry-level visibility gate runs here, so a
visible entry is sent whole. Granting the sync control grants a full copy, and a replica holding partial
entries is not a replica.

# Not Implemented

The following RFCs are not current implemented.

* Server-side VLV. The client can send the control, but the server does not support it.
* SASL GSSAPI. The server offers PLAIN, CRAM-MD5, DIGEST-MD5, EXTERNAL and the SCRAM family.
* The full string preparation algorithm of RFC 4518. Only a subset of the steps runs. See [Schema Validation](Schema.md#string-matching-and-internationalization-rfc-4518).
* Referrals and RFC 3296 `ManageDsaIT`, so the `referral` result code is never returned.
* Syntax validation for Guide (RFC 4517 section 3.3.25) and Enhanced Guide (section 3.3.21).
