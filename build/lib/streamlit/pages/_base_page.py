from abc import ABC, abstractmethod


class BasePageLayout(ABC):
    def __init__(self):  # noqa: B027
        pass

    @abstractmethod
    def page_content(self):
        pass

    def display_page(self):
        self.page_content()
