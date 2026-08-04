def format_api_group(api_group):
    """Render an apiGroup for humans. The core group is an empty string in RBAC."""
    return 'core' if api_group == '' else api_group


# Findings are read as Splunk events, one field per line, so a finding gets one
# line. The rules that matched are already in the 'Rules' field of the same
# event; repeating them under every pattern pushed the rest of the event off the
# screen. '--explain' brings the full block back for a terminal.
_explain = False


def configure_explain(enabled):
    """Switch every finding to its full multi-line block, from --explain."""
    global _explain
    _explain = bool(enabled)


class AppliedModifier:
    """One context rule that moved a finding away from its base priority.

    'explanation' is the sentence a reader gets under --explain. 'detail' is the
    part of it that is not already obvious from the modifier's name - which
    namespace, which group, which service account. A modifier that adds nothing
    beyond its name (a grant is cluster-wide, a role is unbound) leaves it None,
    and the one-line form then shows the name alone.
    """

    def __init__(self, name, delta, explanation, detail=None):
        self.name = name
        self.delta = delta
        self.explanation = explanation
        self.detail = detail

    def render(self):
        return '{sign}{delta} {name} ({explanation})'.format(
            sign='+' if self.delta > 0 else '',
            delta=self.delta,
            name=self.name,
            explanation=self.explanation)

    def render_short(self):
        if self.detail is None:
            return self.name
        return '{0}: {1}'.format(self.name, self.detail)


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

    def rescored(self, priority, modifiers):
        """A detached copy carrying the verdict of a narrower context.

        A single binding is a narrower scope than the role, and scoring one must
        not overwrite the role-level finding: that one is the worst case across
        every binding the role has, and both are reported.
        """
        copy = Finding(self.pattern, list(self.rule_matches))
        copy.priority = priority
        copy.modifiers = list(modifiers)
        return copy

    @property
    def score(self):
        """'CRITICAL', or 'HIGH -> CRITICAL' when context moved the finding."""
        if self.priority == self.base_priority:
            return self.base_priority.name
        return '{0} -> {1}'.format(self.base_priority.name, self.priority.name)

    def render(self):
        """One line: what fired, what it scored, and what made it that severe.

        Those are the only two questions the priority raises, and a reader
        scanning a list of findings should not have to open anything to answer
        them. Everything else about the role is elsewhere in the same event.
        """
        if _explain:
            return self.render_verbose()
        header = '{0}: {1}'.format(self.pattern_name, self.score)
        if not self.modifiers:
            return header
        reasons = ', '.join(modifier.render_short() for modifier in self.modifiers)
        return '{0} ({1})'.format(header, reasons)

    def render_verbose(self):
        """The full block: score arithmetic, matched rules, one modifier per line."""
        lines = ['{0}  {1}'.format(self.pattern_name, self.score)]
        lines += ['  ' + detail for detail in self.match_details]
        lines += ['  ' + modifier.render() for modifier in self.modifiers]
        return '\n'.join(lines)
