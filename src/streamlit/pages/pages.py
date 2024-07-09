from dataclasses import dataclass


@dataclass
class Page:
    filename: str
    label: str


def app_pages():
    """
    Define metadata for pages used in this app.
    """
    return [
        Page("pages/initial_page.py", "Observations Summary"),
        Page("pages/certs.py", "Certificate Stuff Page"),
        Page("pages/metadata.py", "Metadata Stuff Page"),
        Page("pages/debug_page.py", "Debug Stuff Page"),
    ]
