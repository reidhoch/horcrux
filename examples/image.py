from base64 import b64decode, b64encode
from pathlib import Path

import rich
import typer

import shamir

app: typer.Typer = typer.Typer()


@app.command()
def split(filename: str) -> None:
    """Split the file into five shares."""
    with Path(filename).open("rb") as image:
        shares: list[bytearray] = shamir.split(image.read(), 5, 3)
        for idx, share in enumerate(shares):
            with Path(f"{idx}.txt").open("wb") as out:
                rich.print(f"Writing share #{idx} as {idx}.txt")
                out.write(b64encode(share))


@app.command()
def combine(shares: list[str], filename: str) -> None:
    """Combine three or more shares into $FILENAME."""
    parts: list[bytearray] = []
    for share in shares:
        with Path(share).open() as share_input:
            decoded: bytearray = bytearray(b64decode(share_input.read()))
            parts.append(decoded)
    with Path(filename).open("wb") as output:
        rich.print(f"Combing shares into {filename}")
        output.write(shamir.combine(parts))


if __name__ == "__main__":
    app()
