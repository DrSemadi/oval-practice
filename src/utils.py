from src.parser import ast


def strip_oval_name(value: str) -> str:
    value = value.lower()

    return value[5:] if value.startswith('oval:') else value

def resolve_criteria_to_dnf(node: ast.CriteriaNode, *cases: set):
    """
    Resolve criteria subtree into DNF (Disjunctive Normal Form) a.k.a OR of ANDs

    :param node: CriteriaNode - root of criteria subtree;
    :param cases: packed set() of whatever - known cases, do not pass manually;
    :return: generator of sets (ANDs in question)

    Example:
        Input:
            OR
            ├── 2005
            └── AND
                 ├── 2001
                 ├── 2002
                 └── OR
                      ├── 2003
                      └── 2004
        Output:
            (2005)
            (2001, 2002, 2003)
            (2001, 2002, 2004)
    """
    test_cases = []
    child_criteria = []

    for child in node.children:
        if isinstance(child, ast.CriteriaNode):
            child_criteria.append(child)
        else:
            test_cases.append(child)

    match node.operator:
        case 'AND' if cases:
            for case in cases:
                case.update(test_cases)
        case 'AND' if not cases:
            cases = (set(test_cases), )
        case 'OR' if cases:
            new_cases = []

            for test in test_cases:
                for case in cases:
                    new_case = case.copy()
                    new_case.add(test)
                    new_cases.append(new_case)

            cases = new_cases
        case 'OR' if not cases:
            yield from [{item} for item in test_cases]

    if not child_criteria:
        yield from cases
    else:
        for child in child_criteria:
            yield from resolve_criteria_to_dnf(child, *cases)
