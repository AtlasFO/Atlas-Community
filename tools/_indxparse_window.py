"""Run the installed INDXParse with a slack validity window that moves with
the calendar.

INDXParse lists a directory-index slack entry only when all four of its
timestamps fall inside a validity window, and the pinned release closes that
window at a fixed date, so every deletion stamped after it is dropped without
a word. The window is the only guard against slack bytes that merely look
like an entry, so it stays; only its upper bound moves, to the date the
caller passes.

Usage: python _indxparse_window.py <upper ISO date> <INDXParse arguments...>
"""
import sys
from datetime import datetime

# The lower bound INDXParse itself uses.
LOWER = datetime(1990, 1, 1)
_STAMPS = ("modified_time_safe", "accessed_time_safe", "changed_time_safe", "created_time_safe")


def main(argv: list[str]) -> int:
    upper = datetime.fromisoformat(argv[1])
    try:
        from indxparse import INDXParse as indx
        slack, run = indx.NTATTR_DIRECTORY_INDEX_SLACK_ENTRY, indx.main
        for stamp in _STAMPS:
            getattr(slack, stamp)
    except (ImportError, AttributeError) as exc:
        print(f"the installed indxparse lacks what this runner patches: {exc}", file=sys.stderr)
        return 2

    def is_valid(entry) -> bool:
        return all(upper > getattr(entry, s)() > LOWER for s in _STAMPS)

    slack.is_valid = is_valid
    sys.argv = ["INDXParse.py", *argv[2:]]
    return run() or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
