import argparse
import os

import dotenv
import levels
import pwn

dotenv.load_dotenv()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("level", type=int, help="integer between 0-34")
    args = parser.parse_args()

    assert 0 <= args.level <= 34, "Level must be between 0 and 34"

    password = os.getenv(f"BANDIT_PASSWORD{args.level}")
    assert password is not None, f"Password not found for level {args.level}"

    username = f"bandit{args.level}"
    solve = getattr(levels, f"level_{args.level}")

    conn = pwn.ssh(
        host="bandit.labs.overthewire.org", port=2220, user=username, password=password
    )
    solve(conn)


if __name__ == "__main__":
    main()
