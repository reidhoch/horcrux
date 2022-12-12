from base64 import b64decode, b64encode
from pathlib import Path

import rich

import shamir

import typer

app: typer.Typer = typer.Typer()


@app.command()
def split(filename: str) -> None:
    """Split the file into five shares."""
    with open(Path(filename), "rb") as image:
        shares: list[bytearray] = shamir.split(image.read(), 5, 3)
        for idx, share in enumerate(shares):
            with open(f"{idx}.txt", "wb") as out:
                rich.print(f"Writing share #{idx} as {idx}.txt")
                out.write(b64encode(share))


@app.command()
def combine(shares: list[str], filename: str) -> None:
    """Combine three or more shares into $FILENAME."""
    parts: list[bytearray] = []
    for share in shares:
        with open(Path(share)) as share_input:
            decoded: bytearray = bytearray(b64decode(share_input.read()))
            parts.append(decoded)
    with open(Path(filename), "wb") as output:  # noqa: SCS109
        rich.print(f"Combing shares into {filename}")
        output.write(shamir.combine(parts))


if __name__ == "__main__":
    app()
