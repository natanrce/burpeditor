import os
import sys
import json
import shutil

from typing import Optional
from xml.etree import ElementTree as ET

import click

from burpeditor import __version__
from burpeditor.burp import http
from burpeditor.burp.project import BurpProject
from burpeditor.burp.scanner import Severity
from burpeditor.burp.xml_export import read_items
from burpeditor.params import BurpFile, new_project_argument, project_argument

def shorten(text: str, width: int) -> str:
  return text if len(text) <= width else text[:width - 1] + "…"


def echo_bytes(data: Optional[bytes]) -> None:
  if data:
    sys.stdout.buffer.write(data)
    if not data.endswith(b"\n"):
      sys.stdout.buffer.write(b"\n")
    sys.stdout.flush()


@click.group()
@click.version_option(
    __version__,
    "-v",
    "--version",
    message="%(version)s",
    help="Output the current version of burpeditor."
)
def cli() -> None:
  """Edit Burpsuite projects through the CLI"""
  pass


@cli.command()
@new_project_argument()
@click.option("--name", help="Project name (defaults to the file name).")
@click.option("--force", is_flag=True, help="Overwrite PROJECT if it exists.")
def create(file: str, name: Optional[str], force: bool) -> None:
  """Create a new, empty project file."""
  try:
    BurpProject.create(file, name=name, force=force).close()
  except FileExistsError as e:
    raise click.ClickException(f"{e}; use --force to overwrite")
  
  click.echo(f"Created {file}")


@cli.command()
@project_argument()
@click.option("--host", help="Only show items whose host contains this text.")
@click.option("--limit", type=int, help="Show at most this many items.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON lines.")
def history(project: BurpProject, host: Optional[str], limit: Optional[int], as_json: bool) -> None:
  """Show the HTTP requests history of the file."""
  items = [i for i in project.http_history if not host or (i.service and host in i.service.host)]

  for item in items[:limit]:
    if as_json:
      click.echo(json.dumps(item.to_dict()))
    else:
      time = item.time.strftime("%Y-%m-%d %H:%M:%S") if item.time else ""
      flag = "*" if item.edited else " "
      click.echo(f"{item.number:>6}{flag} {item.method:<7} {item.status or '':>3} {item.length:>8} "
                 f"{item.mime:<6} {time:<19}  {shorten(item.url, 100)}")


@cli.command()
@project_argument()
@click.argument("number", type=int)
@click.option("--request/--no-request", default=True, help="Print the request.")
@click.option("--response/--no-response", default=True, help="Print the response.")
def show(project: BurpProject, number: int, request: bool, response: bool) -> None:
  """Print the request and response of a history item."""
  try:
    item = project.http_history.get(number)
  except KeyError as e:
    raise click.ClickException(e.args[0])

  if request:
    echo_bytes(item.request)

  if request and response and item.response:
    click.echo()

  if response:
    echo_bytes(item.response)


def new_message(current: bytes, message_file, use_editor: bool) -> Optional[bytes]:
  """The replacement message from a file or written in $EDITOR, if it changed."""
  if message_file is not None:
    raw = message_file.read()
  elif use_editor:
    text = click.edit(current.decode("latin-1"), extension=".http", require_save=True)
    if text is None:
      return None
    raw = text.encode("latin-1")
  else:
    return None

  return raw if raw != current else None


@cli.command()
@project_argument()
@click.argument("number", type=int)
@click.option("--response", "edit_response", is_flag=True,
              help="Open the response in $EDITOR instead of the request.")
@click.option("--request-file", type=click.File("rb"), help="Raw request to use ('-' for stdin).")
@click.option("--response-file", type=click.File("rb"), help="Raw response to use ('-' for stdin).")
@click.option("--keep-original", is_flag=True,
              help="Keep the original message and store the new one as Burp's 'Edited' version.")
@click.option("-o", "--output", type=BurpFile(exists=False),
              help="Save the result to a new project file instead of overwriting PROJECT.")
def edit(project: BurpProject, number: int, edit_response: bool, request_file, response_file,
         keep_original: bool, output: Optional[str]) -> None:
  """Edit the request and/or response of a history item.

  The request opens in $EDITOR (the response with --response), unless it is
  given with --request-file or --response-file.

  The new message replaces the original one; with --keep-original it is
  stored as the edited version instead, and Burp shows both.

  PROJECT is overwritten (close it in Burp first) unless -o is given.
  """
  try:
    item = project.http_history.get(number)

  except KeyError as e:
    raise click.ClickException(e.args[0])

  no_files = request_file is None and response_file is None
  
  request = new_message(item.request or b"", request_file, no_files and not edit_response)
  response = new_message(item.response or b"", response_file, edit_response and response_file is None)

  if request is None and response is None:
    raise click.ClickException("Nothing changed.")

  if request is not None:
    try:
      http.validate_request(request)
    except ValueError as e:
      raise click.ClickException(str(e))

  path = project.path
  project.close()

  if output and os.path.abspath(output) != os.path.abspath(path):
    shutil.copyfile(path, output)
    target = BurpProject.open(output, writable=True, discard_on_error=True)
  else:
    target = BurpProject.open(path, writable=True)

  with target:
    try:
      if request is not None:
        target.http_history.edit_request(number, request, keep_original=keep_original)

      if response is not None:
        target.http_history.edit_response(number, response, keep_original=keep_original)
    except ValueError as e:
      raise click.ClickException(str(e))

  edited = " and ".join(kind for kind, raw in (("request", request), ("response", response)) if raw is not None)
  click.echo(f"Edited {edited} of #{number} in {target.path}")


@cli.command()
@project_argument()
@click.option("--request-file", type=click.File("rb"), required=True, help="Raw request ('-' for stdin).")
@click.option("--response-file", type=click.File("rb"), help="Raw response.")
@click.option("--http", "plain", is_flag=True, help="The request was sent over plain HTTP (default HTTPS).")
@click.option("-o", "--output", type=BurpFile(exists=False), help="Save the result to a new project file instead of overwriting PROJECT.")
def add(project: BurpProject, request_file, response_file, plain: bool, output: Optional[str]) -> None:
  """Add a request (and optional response) to the HTTP history.

  PROJECT is overwritten (close it in Burp first) unless -o is given.
  """
  request = request_file.read()
  response = response_file.read() if response_file else None

  try:
    http.validate_request(request)
  except ValueError as e:
    raise click.ClickException(str(e))

  path = project.path
  project.close()

  if output and os.path.abspath(output) != os.path.abspath(path):
    shutil.copyfile(path, output)
    target = BurpProject.open(output, writable=True, discard_on_error=True)
  else:
    target = BurpProject.open(path, writable=True)

  with target:
    try:
      number = target.http_history.append(request, response, secure=not plain)
    except ValueError as e:
      raise click.ClickException(str(e))

  click.echo(f"Added request #{number} to {target.path}")


@cli.command("import")
@click.argument("export", type=click.File("rb"))
@new_project_argument()
@click.option("--name", help="Project name (defaults to the file name).")
@click.option("--force", is_flag=True, help="Overwrite PROJECT if it exists.")
def import_items(export, file: str, name: Optional[str], force: bool) -> None:
  """Create a project from items exported by Burp as XML.

  EXPORT is the file written by "Save items" in Burp (Proxy history, site
  map, ...); its items are added to the new project's HTTP history.
  """
  try:
    with BurpProject.create(file, name=name, force=force) as project:
      for item in read_items(export):
        project.http_history.append(item.request, item.response, timestamp=item.time,
                                    service=item.service, ip=item.ip, comment=item.comment)
  except FileExistsError as e:
    raise click.ClickException(f"{e}; use --force to overwrite")
  except (ValueError, ET.ParseError) as e:
    raise click.ClickException(f"Invalid export: {e}")

  click.echo(f"Imported items into {file}")


@cli.command()
@project_argument()
@click.option("--evidence", is_flag=True, help="Print the evidence requests and responses.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON lines.")
def issues(project: BurpProject, evidence: bool, as_json: bool) -> None:
  """Show the scanner issues of the file."""
  found = sorted(project.issues, key=lambda i: (i.severity.rank if i.severity else len(Severity), i.name, i.url))
  
  for issue in found:
    if as_json:
      click.echo(json.dumps(issue.to_dict(evidence)))
      continue
  
    severity = issue.severity.label if issue.severity else "Unknown"
    click.echo(f"{severity:<14} {issue.confidence:<9} {shorten(issue.name, 50):<50}  {issue.url}")

    if evidence:
      for e in issue.evidence:
        echo_bytes(e.request)
        click.echo()
        echo_bytes(e.response)
        click.echo("-" * 80)


@cli.command()
@project_argument()
def tasks(project: BurpProject) -> None:
  """Show the tasks listed in Burp's dashboard."""
  for task in project.tasks:
    state = " (paused)" if task.paused else ""
    click.echo(f"{task.label}{state}")

    if task.configuration:
      click.echo(f"    {task.configuration}")


@cli.command()
@project_argument()
@click.option("--host", help="Only show hosts containing this text.")
@click.option("--urls", is_flag=True, help="List request URLs instead of the tree.")
def sitemap(project: BurpProject, host: Optional[str], urls: bool) -> None:
  """Show the target site map of the file."""
  for root in project.sitemap.hosts():
    if host and host not in root.name:
      continue

    for depth, node in root.walk():
      if urls:
        if node.kind in (3, 4):
          click.echo(f"{node.method or '-':<7} {node.status or '':>3}  {node.url}")
        continue

      extra = f"  [{node.method} {node.status or ''}]" if node.method else ""
      click.echo("  " * depth + node.name + extra)


if __name__ == "__main__":
  cli()

