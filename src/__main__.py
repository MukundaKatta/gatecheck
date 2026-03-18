"""CLI for gatecheck."""
import sys, json, argparse
from .core import Gatecheck

def main():
    parser = argparse.ArgumentParser(description="GateCheck — API Security Scanner. Automated API endpoint security testing and vulnerability detection.")
    parser.add_argument("command", nargs="?", default="status", choices=["status", "run", "info"])
    parser.add_argument("--input", "-i", default="")
    args = parser.parse_args()
    instance = Gatecheck()
    if args.command == "status":
        print(json.dumps(instance.get_stats(), indent=2))
    elif args.command == "run":
        print(json.dumps(instance.detect(input=args.input or "test"), indent=2, default=str))
    elif args.command == "info":
        print(f"gatecheck v0.1.0 — GateCheck — API Security Scanner. Automated API endpoint security testing and vulnerability detection.")

if __name__ == "__main__":
    main()
