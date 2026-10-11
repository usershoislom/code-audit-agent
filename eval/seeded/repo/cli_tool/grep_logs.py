import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser(description="search service logs")
    parser.add_argument("pattern")
    parser.add_argument("--file", default="/var/log/app.log")
    args = parser.parse_args()
    out = subprocess.run(f"grep {args.pattern} {args.file}", shell=True, capture_output=True, text=True)
    print(out.stdout)


if __name__ == "__main__":
    main()
