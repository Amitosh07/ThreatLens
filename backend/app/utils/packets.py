"""Flag parsing shared by statistics and detection."""


def split_flags(value: str | None) -> list[str]:
    if not value:
        return []
    flags: list[str] = []
    for token in value.replace("|", ",").replace(" ", ",").split(","):
        name = token.strip().upper()
        if name and name not in flags:
            flags.append(name)
    return flags
