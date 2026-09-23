"""One account per side of the approval gate, for a demonstration database.

    uv run python lab/replay/demo_users.py --out lab/replay/out/demo_credentials.txt

Bootstrap creates only the administrator, and the gate cannot be shown with one
person: the administrator proposes containment, the analyst decides, the ML engineer
promotes models, and the viewer - the everyday account - reads and changes nothing.
This runs bootstrap and then creates the others through the same function, so they
get the same hashing and the same audit row. Passwords are generated, written once
to ``--out`` and never printed; existing accounts are left alone exactly as bootstrap
leaves the administrator.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from sqlalchemy import select

from netsentinel_api.bootstrap import bootstrap, ensure_admin
from netsentinel_api.db.models import Role
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.rbac import ML_ENGINEER, SOC_ANALYST, VIEWER

ACCOUNTS = (("analyst", SOC_ANALYST), ("modeller", ML_ENGINEER), ("viewer", VIEWER))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    lines = []
    with get_sessionmaker()() as session:
        admin, created, generated = bootstrap(session)
        if created and generated:
            lines.append(f"{admin.username}\t{generated}")
        for username, role_name in ACCOUNTS:
            role = session.scalar(select(Role).where(Role.name == role_name))
            user, created, generated = ensure_admin(
                session, role, username, f"{username}@netsentinel.lab", None
            )
            if created:
                lines.append(f"{user.username}\t{generated}")
        session.commit()

    if lines:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        print(f"{len(lines)} account(s) created; passwords in {args.out}")
    else:
        print("every account already exists; nothing written")


if __name__ == "__main__":
    main()
