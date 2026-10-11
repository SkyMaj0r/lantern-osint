from __future__ import annotations

import asyncio

import typer
from rich.console import Console

from lantern.core.cache import Cache
from lantern.core.dispatcher import Dispatcher
from lantern.core.entities import EntityType
from lantern.core.models import Finding
from lantern.core.settings import Settings, SettingsError, get_settings
from lantern.core.ssrf import build_guarded_client
from lantern.modules.base import Context
from lantern.modules.darknet.ransomware_live import fetch_groups, fetch_recent_victims
from lantern.modules.email.pwned_passwords import PwnedPasswordsError, check_password
from lantern.modules.registry import default_collectors

app = typer.Typer(add_completion=False, help="Lantern — modular OSINT aggregation tool.")
darknet_app = typer.Typer(add_completion=False, help="Darknet reference lookups (not entity-driven).")
app.add_typer(darknet_app, name="darknet")
console = Console()

COLLECTORS = default_collectors()


@app.command()
def search(
    query: str,
    source: list[str] = typer.Option(
        None, "--source", help="Restrict to this collector (repeatable). Default: every applicable one."
    ),
    type_: str = typer.Option(
        None,
        "--type",
        help=(
            "Force the query's type instead of auto-detecting "
            "(email|ip|domain|username|person|company). Skips the other types' modules."
        ),
    ),
) -> None:
    """Search a name, username, email, domain, IP, or company."""
    try:
        settings = get_settings()
    except SettingsError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    entity_type: EntityType | None = None
    if type_ is not None:
        try:
            entity_type = EntityType(type_.lower())
        except ValueError:
            valid = ", ".join(t.value for t in EntityType)
            console.print(f"[red]Unknown --type {type_!r}. Choose one of: {valid}.[/red]")
            raise typer.Exit(code=1)

    asyncio.run(_run_search(query, settings, set(source) if source else None, entity_type))


async def _run_search(
    query: str,
    settings: Settings,
    enabled: set[str] | None = None,
    entity_type: EntityType | None = None,
) -> None:
    client = build_guarded_client()
    ctx = Context(http=client, cache=Cache(settings.cache_path), settings=settings)
    dispatcher = Dispatcher(COLLECTORS, make_context=lambda: ctx)

    console.print(f"Searching for [bold]{query}[/bold]...\n")
    count = 0
    try:
        async for finding in dispatcher.stream(query, enabled, entity_type):
            count += 1
            console.print(
                f"[bold blue]{finding.source}[/bold blue] · {_label(finding)} "
                f"[dim](confidence {finding.confidence:.2f})[/dim]"
            )
            if finding.url:
                console.print(f"  {finding.url}")
    except ValueError as exc:
        # Raised by the type override when the query doesn't match the forced
        # type (e.g. --type ip on something that isn't an IP).
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    finally:
        await client.aclose()

    console.print()
    if count == 0:
        console.print(f"No findings for {query!r}.")
    else:
        console.print(f"{count} finding(s).")


def _label(finding: Finding) -> str:
    for key in ("site", "breach", "cve", "group", "computer_name"):
        if key in finding.data:
            return str(finding.data[key])
    return finding.value


@app.command("check-password")
def check_password_command(
    password: str = typer.Argument(..., help="Only a 5-char SHA-1 prefix is ever sent, never the password."),
) -> None:
    """Check whether a password has appeared in known breaches (HIBP Pwned Passwords)."""
    try:
        settings = get_settings()
    except SettingsError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    asyncio.run(_run_check_password(password, settings))


async def _run_check_password(password: str, settings: Settings) -> None:
    client = build_guarded_client()
    try:
        count = await check_password(password, client, settings.user_agent)
    except PwnedPasswordsError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    finally:
        await client.aclose()

    if count == 0:
        console.print("Not found in any known breach.")
    else:
        console.print(f"[bold red]Found in {count:,} breach record(s).[/bold red] Change this password.")


@darknet_app.command("recent")
def darknet_recent(limit: int = 20) -> None:
    """Latest ransomware victims disclosed on Ransomware.live."""
    try:
        settings = get_settings()
    except SettingsError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    asyncio.run(_run_darknet_recent(limit, settings))


async def _run_darknet_recent(limit: int, settings: Settings) -> None:
    client = build_guarded_client()
    ctx = Context(http=client, cache=Cache(settings.cache_path), settings=settings)
    try:
        victims = await fetch_recent_victims(ctx, limit=limit)
    finally:
        await client.aclose()

    if not victims:
        console.print("No recent victims available (source may be temporarily unavailable).")
        return
    for victim in victims:
        console.print(
            f"[bold blue]{victim.get('group', '?')}[/bold blue] · {victim.get('victim', '?')} "
            f"[dim]({victim.get('country', '?')}, {victim.get('attackdate', '?')})[/dim]"
        )


@darknet_app.command("groups")
def darknet_groups() -> None:
    """List known ransomware groups tracked by Ransomware.live."""
    try:
        settings = get_settings()
    except SettingsError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    asyncio.run(_run_darknet_groups(settings))


async def _run_darknet_groups(settings: Settings) -> None:
    client = build_guarded_client()
    ctx = Context(http=client, cache=Cache(settings.cache_path), settings=settings)
    try:
        groups = await fetch_groups(ctx)
    finally:
        await client.aclose()

    if not groups:
        console.print("No group data available (source may be temporarily unavailable).")
        return
    for group in groups:
        name = group.get("name") or group.get("group_name") or str(group)
        console.print(name)


if __name__ == "__main__":
    app()
