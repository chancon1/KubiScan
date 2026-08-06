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
        # Every rule of the role that grants this one pattern rule. Usually just
        # the one, but a role can grant the same permission twice, and scoring
        # has to see all of them: a 'resourceNames' restriction narrows the
        # grant only when no unrestricted rule offers the same thing.
        self.source_rules = [source_rule]

    @classmethod
    def merged(cls, matches):
        """Fold every rule that satisfied one pattern rule into a single match.

        Keeping only the first made two things go wrong. The verdict depended on
        the order the rules happened to be written in, and a narrow rule could
        hide a broad one standing right next to it - the shape every leader
        election uses, where 'get'/'update' are pinned by name and 'create' is
        not.
        """
        primary = matches[0]
        if len(matches) == 1:
            return primary
        granted = set()
        for match in matches:
            granted.update(match.matched_verbs)
        # Ordered by the pattern rather than by the role, so that two roles
        # granting the same thing read identically in a report.
        verbs = [verb for verb in (primary.pattern_rule.verbs or []) if verb in granted]
        merged = cls(primary.source_rule, primary.pattern_rule, verbs,
                     primary.matched_resources)
        merged.source_rules = [match.source_rule for match in matches]
        return merged

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
        # What the permission lets you do, once context has narrowed or widened
        # the capability itself.
        self.severity = pattern.base_priority
        # The same, plus where the grant lands and who holds it. What a reviewer
        # should look at first.
        self.priority = pattern.base_priority
        self.rule_matches = rule_matches or []
        self.modifiers = []

    @property
    def match_details(self):
        return [match.render() for match in self.rule_matches]

    def rescored(self, severity, priority, modifiers):
        """A detached copy carrying the verdict of a narrower context.

        A single binding is a narrower scope than the role, and scoring one must
        not overwrite the role-level finding: that one is the worst case across
        every binding the role has, and both are reported.
        """
        copy = Finding(self.pattern, list(self.rule_matches))
        copy.severity = severity
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
