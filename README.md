# burpeditor

Inspect and edit Burp Suite `.burp` project files from the command line, without Burp.

## Installation

```bash
pipx install burpeditor
```

### Editing history items

Commands that modify a project overwrite it; use `-o/--output new.burp` to save
the result to a new file and keep the original. Close the project in Burp first.

```bash
# Open the request in $EDITOR (the response with --response)
burpeditor edit project.burp 12
burpeditor edit project.burp 12 --response

# Replace messages with files, saving to a new project
burpeditor edit project.burp 12 --request-file request.txt --response-file response.txt -o edited.burp
```

By default the new message replaces the original one (and any auto-modified or
edited versions), so Burp shows it directly. With `--keep-original` it is stored
the way Burp stores a message changed in the interceptor: Burp keeps the
original and offers both in the message viewer (Original/Edited). Item metadata
that Burp derives from the messages (method, URL, host, extension, parameters,
status, MIME type, length, title, cookies) is updated too; the site map is not.
Line endings are normalized to CRLF, and a request with a body but no
Content-Length gets one; an existing Content-Length is kept as written.

`import` reads the XML that Burp writes with "Save items" (Proxy history, site
map, ...) and adds every item to the new project's HTTP history, keeping the
host, port, protocol, IP, time and comment of each item. The export only has
second precision for times.

New items can be added to the history with
`burpeditor add project.burp --request-file req.txt [--response-file resp.txt] [--http]`.

## How it works

A `.burp` file is a memory-mapped object heap with a bump allocator. Objects
are records (`flags, type, schema version, field count, field descriptors,
values`) and primitive arrays, linked by absolute 64-bit offsets. burpeditor
reads that object graph directly, and writes by allocating new objects at the
end of the heap and updating pointers, as Burp does. `burpeditor/burp/store.py`
documents the layout.

`create` writes the objects Burp allocates for a new project (the application
root, its tools and the default project options), taken from a real project
with all data collections and identifiers removed, and then fills in fresh
empty collections, random identifiers and the project name.

Files are written in format version 222; newer Burp versions upgrade them when
the project is opened. Projects created or edited by burpeditor have not been
verified against every Burp release, so keep a copy of anything important.

## Acknowledgements

Special thanks to [bmm-sec/burp-insights](https://github.com/bmm-sec/burp-insights) for inspiration.

## Disclaimer

This tool is not a replacement for Burp Suite Professional. It is designed to complement and extend existing security testing workflows, particularly when working with exported HTTP traffic. Features provided by Burp Suite Professional remain outside the scope of this project.

Imported requests and responses may be editable for experimentation, replay, annotation, or analysis. However, do not modify original data when it is being used as proof of concept.

## License

Distributed under the Apache-2.0 License. See [LICENSE](https://github.com/natanrce/burpeditor/blob/main/LICENSE) for more information.
