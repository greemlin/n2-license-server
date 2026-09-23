"""Generate an admin password hash for the N2 License Server."""
from __future__ import annotations

import bcrypt


def main() -> None:
    import getpass

    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match")
        return
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    print(f"\nADMIN_PASSWORD_HASH={hashed}")


if __name__ == "__main__":
    main()
