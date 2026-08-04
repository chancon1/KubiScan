def format_api_group(api_group):
    """Render an apiGroup for humans. The core group is an empty string in RBAC."""
    return 'core' if api_group == '' else api_group


class AppliedModifier:
    """One context rule that moved a finding away from its base priority."""

    def __init__(self, name, delta, explanation):
        self.name = name
        self.delta = delta
        self.explanation = explanation

    def render(self):
        return '{sign}{delta} {name} ({explanation})'.format(
            sign='+' if self.delta > 0 else '',
            delta=self.delta,
            name=self.name,
            explanation=self.explanation)


class RuleMatch:
    """The rule of a scanned role that satisfied one rule of a pattern.

    Keeping the source rule around (rather than only a rendered string) is what
    lets scoring look at 'resourceNames' afterwards, and what lets a report say
    which apiGroup the finding actually came from.
    """

    def __init__(self, source_rule, pattern_rule, matched_verbs, matched_resources):
        self.source_rule = source_rule
        self.pattern_rule = pattern_rule
        self.matched_verbs = matched_verbs
        self.matched_resources = matched_resources

    def render(self):
        """e.g. "[core] secrets: get,list" - apiGroup included, not just the name."""
        groups = ','.join(format_api_group(g)
                          for g in (self.source_rule.api_groups or ['?']))
        target = ','.join(self.matched_resources) or ','.join(
            getattr(self.source_rule, 'non_resource_ur_ls', None) or ['?'])
        return '[{0}] {1}: {2}'.format(groups, target, ','.join(self.matched_verbs))


class Finding:
    """One pattern matching one role, scored in the context of the whole scan.

    'base_priority' is what the pattern declares for the plain namespaced case.
    'priority' is what the context made of it; the two are equal until scoring
    runs, and the difference is explained by 'modifiers'.
    """

    def __init__(self, pattern, rule_matches=None):
        self.pattern = pattern
        self.pattern_name = pattern.name
        self.base_priority = pattern.base_priority
        self.category = pattern.category
        self.priority = pattern.base_priority
        self.rule_matches = rule_matches or []
        self.modifiers = []

    @property
    def match_details(self):
        return [match.render() for match in self.rule_matches]

    def render(self):
        """Pattern name, the score arithmetic, and the rules behind it."""
        if self.priority == self.base_priority:
            header = '{0}  {1}'.format(self.pattern_name, self.base_priority.name)
        else:
            header = '{0}  {1} -> {2}'.format(self.pattern_name, self.base_priority.name,
                                              self.priority.name)
        lines = [header]
        lines += ['  ' + detail for detail in self.match_details]
        lines += ['  ' + modifier.render() for modifier in self.modifiers]
        return '\n'.join(lines)
