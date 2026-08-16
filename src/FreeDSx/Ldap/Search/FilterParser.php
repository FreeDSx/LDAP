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

namespace FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Exception\FilterParseException;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;

/**
 * Parses LDAP filter strings. RFC 4515.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class FilterParser
{
    /**
     * ABNF string literals are case insensitive (RFC 4234 2.3), so ":dn" may be given in any case.
     */
    private const MATCHING_RULE = '/^([a-zA-Z0-9\.]+)?(\:dn)?(\:([a-zA-Z0-9\.]+))?$/i';

    private string $filter;

    private int $length;

    private int $depth = 0;

    /**
     * @var null|array<int, array{startAt?: int, endAt: null|int}>
     */
    private ?array $containers = null;

    public function __construct(string $filter)
    {
        $this->filter = $filter;
        $this->length = strlen($filter);
    }

    /**
     * @throws FilterParseException
     */
    public static function parse(string $filter): FilterInterface
    {
        if ($filter === '') {
            throw new FilterParseException('The filter cannot be empty.');
        }

        return (new self($filter))->parseFilterString(0, true)[1];
    }

    /**
     * @return array{0: ?int, 1: FilterInterface}
     * @throws FilterParseException
     */
    private function parseFilterString(
        int $startAt,
        bool $isRoot = false,
    ): array {
        if ($this->isAtFilterContainer($startAt)) {
            [$endsAt, $filter] = $this->parseFilterContainer($startAt, $isRoot);
        } else {
            [$endsAt, $filter] = $this->parseComparisonFilter($startAt, $isRoot);
        }
        if ($isRoot && $endsAt !== $this->length) {
            throw new FilterParseException(sprintf(
                'Unexpected value at end of the filter: %s',
                substr($this->filter, $endsAt),
            ));
        }

        return [$endsAt, $filter];
    }

    private function isAtFilterContainer(int $pos): bool
    {
        if (!$this->startsWith(FilterInterface::PAREN_LEFT, $pos)) {
            return false;
        }

        foreach (FilterInterface::OPERATORS as $compOp) {
            if ($this->startsWith($compOp, $pos + 1)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse a filter container. Always returns the ending position followed by the filter container.
     *
     * @return array{0: int, 1: FilterInterface}
     * @throws FilterParseException
     */
    private function parseFilterContainer(
        int $startAt,
        bool $isRoot,
    ): array {
        if ($this->containers === null) {
            $this->parseContainerDepths();
        }
        $this->depth += $isRoot ? 0 : 1;
        if (!isset($this->containers[$this->depth])) {
            throw new FilterParseException(sprintf(
                'The container at position %s is unrecognized. Perhaps there\'s an unmatched "(".',
                $startAt,
            ));
        }
        $endAt = $this->containers[$this->depth]['endAt'] ?? 0;
        $operator = substr($this->filter, $startAt + 1, 1);

        if ($operator === FilterInterface::OPERATOR_NOT) {
            return [$endAt, $this->getNotFilterObject($startAt, $endAt)];
        }

        $startAt += 2;
        $filter = $operator === FilterInterface::OPERATOR_AND ? new AndFilter() : new OrFilter();
        while ($endAt !== ($startAt + 1)) {
            [$startAt, $childFilter] = $this->parseFilterString($startAt ?? 0);
            $filter->add($childFilter);
        }

        return [$endAt, $filter];
    }

    /**
     * Parse a comparison operator. Always returns the ending position followed by the filter.
     *
     * @return array{0: int, 1: FilterInterface}
     * @throws FilterParseException
     */
    private function parseComparisonFilter(
        int $startAt,
        bool $isRoot = false,
    ): array {
        $parenthesis = $this->validateComparisonFilter($startAt, $isRoot);
        $endAt = !$parenthesis && $isRoot ? $this->length : $this->nextClosingParenthesis($startAt) + 1;

        $attributeEndsAfter = null;
        $filterType = null;
        $valueStartsAt = null;
        for ($i = $startAt; $i < $endAt; $i++) {
            foreach (FilterInterface::FILTERS as $op) {
                if ($this->filter[$i] === $op) {
                    $filterType = $op;
                } elseif (($i + 1) < $endAt && $this->filter[$i] . $this->filter[$i + 1] === $op) {
                    $filterType = $op;
                }
                if ($filterType !== null) {
                    break;
                }
            }
            if ($filterType !== null) {
                $attributeEndsAfter = $i - $startAt;
                $valueStartsAt = $i + strlen($filterType);
                break;
            }
        }
        $this->validateParsedFilter($filterType, $startAt, $valueStartsAt, $endAt);

        $attribute = substr(
            $this->filter,
            $startAt + ($parenthesis ? 1 : 0),
            (int) $attributeEndsAfter - ($parenthesis ? 1 : 0),
        );
        $value = substr(
            $this->filter,
            (int) $valueStartsAt,
            $endAt - (int) $valueStartsAt - ($parenthesis ? 1 : 0),
        );

        if ($attribute === '') {
            throw new FilterParseException(sprintf(
                'The attribute is missing in the filter near position %s.',
                $startAt,
            ));
        }

        return [$endAt, $this->getComparisonFilterObject((string) $filterType, $attribute, $value)];
    }

    /**
     * Validates some initial filter logic and determines if the filter is wrapped in parenthesis (validly).
     *
     * @throws FilterParseException
     */
    private function validateComparisonFilter(
        int $startAt,
        bool $isRoot,
    ): bool {
        $parenthesis = true;

        # A filter without an opening parenthesis is only valid if it is the root. And it cannot have a closing parenthesis.
        if ($isRoot && !$this->startsWith(FilterInterface::PAREN_LEFT, $startAt)) {
            $parenthesis = false;
            $pos = false;
            try {
                $pos = $this->nextClosingParenthesis($startAt);
            } catch (FilterParseException) {
            }
            if ($pos !== false) {
                throw new FilterParseException(sprintf('The ")" at char %s has no matching parenthesis', $pos));
            }
            # If this is not a root filter, it must start with an opening parenthesis.
        } elseif (!$isRoot && !$this->startsWith(FilterInterface::PAREN_LEFT, $startAt)) {
            throw new FilterParseException(sprintf(
                'The character "%s" at position %s was unexpected. Expected "(".',
                $this->filter[$startAt],
                $startAt,
            ));
        }

        return $parenthesis;
    }

    /**
     * Validate some basic aspects of the filter after it is parsed.
     *
     * @throws FilterParseException
     */
    private function validateParsedFilter(
        ?string $filterType,
        ?int $startsAt,
        ?int $startValue,
        int $endAt,
    ): void {
        if ($filterType === null) {
            throw new FilterParseException(sprintf(
                'Expected one of "%s" in the filter after position %s, but received none.',
                implode(', ', FilterInterface::FILTERS),
                $startsAt,
            ));
        }
        // RFC 4515 3: valueencoding permits an empty assertion value, as in the "(seeAlso=)" example of section 4.
        if ($startValue === null) {
            throw new FilterParseException(sprintf(
                'Expected a value after "%s" at position %s, but got none.',
                $filterType,
                $startValue,
            ));
        }
    }

    /**
     * @throws FilterParseException
     */
    private function getComparisonFilterObject(
        string $operator,
        string $attribute,
        string $value,
    ): FilterInterface {
        if ($operator === FilterInterface::FILTER_LTE) {
            return Filters::lessThanOrEqual($attribute, $this->unescapeValue($value));
        } elseif ($operator === FilterInterface::FILTER_GTE) {
            return Filters::greaterThanOrEqual($attribute, $this->unescapeValue($value));
        } elseif ($operator === FilterInterface::FILTER_APPROX) {
            return Filters::approximate($attribute, $this->unescapeValue($value));
        } elseif ($operator === FilterInterface::FILTER_EXT) {
            return $this->getMatchingRuleFilterObject($attribute, $this->unescapeValue($value));
        }

        if ($value === '*') {
            return Filters::present($attribute);
        }

        if (preg_match('/\*/', $value) !== 0) {
            return $this->getSubstringFilterObject($attribute, $value);
        } else {
            return Filters::equal($attribute, $this->unescapeValue($value));
        }
    }

    /**
     * @throws FilterParseException
     */
    private function getMatchingRuleFilterObject(
        string $attribute,
        string $value,
    ): MatchingRuleFilter {
        if (preg_match(self::MATCHING_RULE, $attribute, $matches) === 0) {
            throw new FilterParseException(sprintf('The matching rule is not valid: %s', $attribute));
        }
        $matchRuleObj = new MatchingRuleFilter(null, null, $value);

        $matchingRule = $matches[4] ?? '';
        $attrName = $matches[1] ?? '';
        // An optional group that did not take part still reports as set, holding an empty string.
        $useDnAttr = ($matches[2] ?? '') !== '';

        # RFC 4511, 4.5.1.7.7: If the matchingRule field is absent, the type field MUST be present [..]
        if ($matchingRule === '' && $attrName === '') {
            throw new FilterParseException(sprintf(
                'If the matching rule is absent the attribute type must be present, but it is not: %s',
                $attribute,
            ));
        }

        if ($attrName !== '') {
            $matchRuleObj->setAttribute($attrName);
        }
        if ($matchingRule !== '') {
            $matchRuleObj->setMatchingRule($matchingRule);
        }
        $matchRuleObj->setUseDnAttributes($useDnAttr);

        return $matchRuleObj;
    }

    /**
     * @throws FilterParseException
     */
    private function getSubstringFilterObject(
        string $attribute,
        string $value,
    ): SubstringFilter {
        $filter = new SubstringFilter($attribute);
        $substrings = preg_split('/\*/', $value, -1, PREG_SPLIT_OFFSET_CAPTURE | PREG_SPLIT_NO_EMPTY);
        if (!is_array($substrings)) {
            throw new FilterParseException(sprintf(
                'Unable to parse the substring filter for attribute %s.',
                $attribute,
            ));
        }

        $contains = [];
        foreach ($substrings as $substring) {
            $substringValue = $this->unescapeValue($substring[0]);
            $substringType = (int) $substring[1];

            // The offset and the length both have to be of the raw fragment for the end of the value to line up.
            if ($substringType === 0) {
                $filter->setStartsWith($substringValue);
            } elseif (($substringType + strlen($substring[0])) === strlen($value)) {
                $filter->setEndsWith($substringValue);
            } else {
                $contains[] = $substringValue;
            }
        }
        $filter->setContains(...$contains);

        return $filter;
    }

    /**
     * @throws FilterParseException
     */
    private function getNotFilterObject(
        int $startAt,
        int $endAt,
    ): FilterInterface {
        // RFC 4515 3: "not" negates any single filter, including a nested container.
        $info = $this->parseFilterString($startAt + 2);
        if (($info[0] + 1) !== $endAt) {
            throw new FilterParseException(sprintf(
                'The value after the "not" filter value was unexpected: %s',
                substr($this->filter, $info[0] + 1, $endAt - ((int) $info[0] + 1)),
            ));
        }

        return Filters::not($info[1]);
    }

    private function startsWith(
        string $char,
        int $pos,
    ): bool {
        return isset($this->filter[$pos])
            && $this->filter[$pos] === $char;
    }

    /**
     * This seems like a potential minefield. But the general idea is to loop through the complete filter to get the
     * start and end positions of each container along the way. The container index marks the depth, with the lowest (0)
     * being the furthest out and the higher numbers being closer inside. We skip positions inside the for loop when a
     * comparison filter is encountered to only capture beginning and end parenthesis of containers.
     *
     * Each container encountered has its end point marked by detecting the closing parenthesis then we loop through known
     * detected containers starting at the highest level that have no endpoints marked yet and working our way down.
     *
     * @throws FilterParseException
     */
    private function parseContainerDepths(): void
    {
        $this->containers = $this->containers ?? [];

        $child = null;
        for ($i = 0; $i < $this->length; $i++) {
            # Detect an unescaped left parenthesis
            if ($this->filter[$i] === FilterInterface::PAREN_LEFT) {
                [$i, $child] = $this->parseContainerStart((int) $i, $child);
                # We have reached a closing parenthesis of a container, work backwards from those defined to set the ending.
            } elseif ($this->filter[$i] === FilterInterface::PAREN_RIGHT) {
                $this->parseContainerEnd((int) $i);
            }
        }

        if ($this->containers !== null) {
            foreach ($this->containers as $info) {
                if ($info['endAt'] === null) {
                    throw new FilterParseException('The filter has an unmatched "(".');
                }
            }
        }
    }

    /**
     * @throws FilterParseException
     */
    private function nextClosingParenthesis(int $startAt): int
    {
        for ($i = $startAt; $i < $this->length; $i++) {
            # Look for the char, but ignore it if it is escaped
            if ($this->filter[$i] === FilterInterface::PAREN_RIGHT) {
                return $i;
            }
        }

        throw new FilterParseException(sprintf(
            'Expected a matching ")" after position %s, but none was found',
            $startAt,
        ));
    }

    /**
     * @throws FilterParseException
     */
    private function unescapeValue(string $value): string
    {
        $this->assertValueEncoding($value);

        return (string) preg_replace_callback(
            '/\\\\([0-9A-Fa-f]{2})/',
            fn(array $matches) => (string) hex2bin($matches[1]),
            $value,
        );
    }

    /**
     * RFC 4515 3: an assertion value is UTF1SUBSET, UTFMB, or an escape of exactly two hex digits.
     *
     * UTF1SUBSET excludes NUL, the parentheses, the asterisk and the backslash.
     *
     * @throws FilterParseException
     */
    private function assertValueEncoding(string $value): void
    {
        if (preg_match('/\\\\(?![0-9A-Fa-f]{2})/', $value) === 1) {
            throw new FilterParseException(
                'A "\" in an assertion value must be followed by two hex digits.',
            );
        }

        if (preg_match('/[\x00()*]/', $value) === 1) {
            throw new FilterParseException(
                'An assertion value cannot hold an unescaped NUL, parenthesis or asterisk.',
            );
        }
    }

    /**
     * @return array{0: int, 1: ?int}
     *
     * @throws FilterParseException
     */
    private function parseContainerStart(int $i, ?int $child): array
    {
        $operator = $this->filter[$i + 1] ?? null;

        # No leading operator → standard comparison filter; jump to its closing paren.
        if ($operator === null || !in_array($operator, FilterInterface::OPERATORS, true)) {
            return [$this->nextClosingParenthesis($i + 1), $child];
        }

        $child = $child === null ? 0 : $child + 1;
        $this->containers[$child] = ['startAt' => $i, 'endAt' => null];

        return [$this->advancePastContainerBody($operator, $i + 2), $child];
    }

    /**
     * Returns the position the outer scan should resume from, given the operator and the index immediately after it.
     *
     * @throws FilterParseException
     */
    private function advancePastContainerBody(
        string $operator,
        int $i,
    ): int {
        # Nested logical container — step back one so the outer scan re-enters at its '('.
        if ($this->isAtFilterContainer($i)) {
            return $i - 1;
        }

        $char = $this->filter[$i] ?? null;

        # Comparison filter inside the container.
        if ($char === FilterInterface::PAREN_LEFT) {
            return $this->nextClosingParenthesis($i);
        }

        # RFC 4526: (&) and (|) are the absolute true / false filters; only "!" requires an operand.
        if ($char === FilterInterface::PAREN_RIGHT && $operator !== FilterInterface::OPERATOR_NOT) {
            return $i - 1;
        }

        if ($char === FilterInterface::PAREN_RIGHT) {
            throw new FilterParseException(sprintf(
                'The filter container near position %s is empty.',
                $i,
            ));
        }

        throw new FilterParseException(sprintf(
            'Unexpected value after "%s" at position %s: %s',
            $this->filter[$i - 1] ?? '',
            $i + 1,
            $this->filter[$i + 1] ?? '',
        ));
    }

    /**
     * @throws FilterParseException
     */
    private function parseContainerEnd(int $i): void
    {
        $matchFound = false;
        foreach (array_reverse((array) $this->containers, true) as $ci => $info) {
            if ($info['endAt'] === null) {
                $this->containers[$ci]['endAt'] = $i + 1;
                $matchFound = true;
                break;
            }
        }
        if (!$matchFound) {
            throw new FilterParseException(sprintf(
                'The closing ")" at position %s has no matching parenthesis',
                $i,
            ));
        }
    }
}
