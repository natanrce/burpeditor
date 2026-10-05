from typing import Any, Optional

import click

from burpeditor.burp.project import BurpProject
from burpeditor.burp.store import StoreError, is_project_file

class BurpFile(click.Path):
  """Path to a .burp project.

  With `exists` the file must already be a Burp Suite project; otherwise only
  the extension is checked, for files about to be created.
  """
  name = "burp_file"

  def __init__(self, exists: bool = True) -> None:
    super().__init__(exists=exists, dir_okay=False, path_type=str)

  def convert(self, value: Any, param: Optional[click.Parameter], ctx: Optional[click.Context]) -> str:
    path = super().convert(value, param, ctx)

    if not path.endswith(".burp"):
      self.fail(f"{click.format_filename(path)!r} must have the .burp extension.", param, ctx)

    if self.exists and not is_project_file(path):
      self.fail(f"{click.format_filename(path)!r} is not a Burp Suite project.", param, ctx)

    return path

class BurpProjectFile(BurpFile):
  """An existing .burp project, opened read-only and closed with the command."""
  name = "burp_project"

  def __init__(self) -> None:
    super().__init__(exists=True)

  def convert(self, value: Any, param: Optional[click.Parameter], ctx: Optional[click.Context]) -> BurpProject:
    if isinstance(value, BurpProject):
      return value

    path = super().convert(value, param, ctx)

    try:
      project = BurpProject.open(path)
    except (StoreError, ValueError) as e:
      self.fail(f"{click.format_filename(path)!r}: {e}", param, ctx)

    if ctx is not None:
      ctx.call_on_close(project.close)

    return project

def project_argument():
  """The PROJECT argument of a command, passed to it opened as `project`."""
  return click.argument("project", type=BurpProjectFile(), metavar="PROJECT")

def new_project_argument():
  """The PROJECT argument of a command that creates it, passed as the path `file`."""
  return click.argument("file", type=BurpFile(exists=False), metavar="PROJECT")
