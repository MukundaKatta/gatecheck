"""Basic usage example for gatecheck."""
from src.core import Gatecheck

def main():
    instance = Gatecheck(config={"verbose": True})

    print("=== gatecheck Example ===\n")

    # Run primary operation
    result = instance.detect(input="example data", mode="demo")
    print(f"Result: {result}")

    # Run multiple operations
    ops = ["detect", "scan", "monitor]
    for op in ops:
        r = getattr(instance, op)(source="example")
        print(f"  {op}: {"✓" if r.get("ok") else "✗"}")

    # Check stats
    print(f"\nStats: {instance.get_stats()}")

if __name__ == "__main__":
    main()
