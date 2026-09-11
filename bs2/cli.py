import argparse
import json
import os
from . import __version__
from .memory import BattleMemory
from .session import check_private_read


def main():
    parser = argparse.ArgumentParser(description="BS2 bounded, governed assessment session")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--run-dir", default=os.environ.get("BS2_RUN_DIR"))
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("context")
    sub.add_parser("state")
    check = sub.add_parser("check-read")
    for name in ("base", "route", "identity-route", "owner", "other", "resource-id", "private-contract", "generation", "session-epoch"):
        check.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if not args.run_dir:
        parser.error("--run-dir or BS2_RUN_DIR is required")
    if args.verb == "context":
        result = BattleMemory(args.run_dir).context()
    elif args.verb == "state":
        result = BattleMemory(args.run_dir).panel()
    else:
        if not os.environ.get("BS2_OWNER_TOKEN") or not os.environ.get("BS2_OTHER_TOKEN"):
            parser.error("BS2_OWNER_TOKEN and BS2_OTHER_TOKEN must contain the provisioned test credentials")
        result = check_private_read(args.run_dir, base=args.base, route=args.route, identity_route=args.identity_route,
                                    owner=(args.owner, os.environ["BS2_OWNER_TOKEN"]), other=(args.other, os.environ["BS2_OTHER_TOKEN"]),
                                    resource_id=args.resource_id, private_contract=args.private_contract,
                                    generation=args.generation, session_epoch=args.session_epoch)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
