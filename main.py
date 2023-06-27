#
#
#
import sys


def main() -> int:

    return 0


if __name__ == "__main__":
    result = 0
    try:
        result = main() or 0
    except KeyboardInterrupt:
        print("Ctrl+C")
    except Exception as e:
        print(f"Unexpected exception occured in main(): {e}")
        result = 1
    finally:
        sys.exit(result)
