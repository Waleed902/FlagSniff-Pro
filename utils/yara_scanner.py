# utils/yara_scanner.py

import yara

def scan_with_yara(data, rule_filepaths):
    """
    Scans data with a given set of YARA rules.
    """
    matches = []

    try:
        rules = yara.compile(filepaths={f'namespace_{i}': fp for i, fp in enumerate(rule_filepaths)})

        for match in rules.match(data=data):
            matches.append({
                'rule': match.rule,
                'tags': match.tags,
                'strings': [{s.identifier: s.strings} for s in match.strings],
            })

    except yara.Error as e:
        # Handle YARA errors (e.g., invalid rule syntax)
        print(f"YARA Error: {e}")

    return matches
