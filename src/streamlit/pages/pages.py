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
        Page("pages/certs.py", "Certificate Information"),
        Page("pages/metadata.py", "Scanned File Metadata"),
        Page("pages/debug_page.py", "Debug Page"),
    ]
