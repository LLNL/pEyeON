import common.page_frags as pf
from pages._base_page import BasePageLayout
from pages.pages import app_pages
from common.utils import sidebar_config
from utils.config import settings

# import pandas as pd
import streamlit as st
import altair as alt
import common.dqautil as du


class LandingPage(BasePageLayout):
    def __init__(self):
        super().__init__()

    def page_content(self):
        st.set_page_config(
            page_icon=settings.app.logo, page_title="Metadata Summary", layout="wide"
        )
        sidebar_config(app_pages())
        st.header("Metadata Visualization")

        st.markdown("#### File sizes")
        filesize_df = du.getdatafor(du.getcon(), "file_sizes")
        st.altair_chart(
            alt.Chart(filesize_df)
            .mark_bar()
            .encode(
                x=alt.X("bytecount:Q", bin=alt.Bin(maxbins=50, extent=(0, 30000000))),
                y=alt.Y("count()").scale(type="log"),
            )
            .interactive(),
            use_container_width=True,
        )

        st.markdown("#### File extensions")
        extension_df = du.getdatafor(du.getcon(), "file_extensions")
        # This horizontal barchart needs at least streamlit v1.36 I think
        st.altair_chart(
            alt.Chart(extension_df)
            .mark_bar()
            .encode(
                x=alt.X("file_extension", sort=None),
                y="NumRows",
            )
            .interactive(),
            use_container_width=True,
        )

        st.markdown("#### Magic Bytes")
        magic_df = du.getdatafor(du.getcon(), "magic_bytes")
        # st.bar_chart(magic_df, x="magic", y="NumRows")
        st.altair_chart(
            alt.Chart(magic_df)
            .mark_bar()
            .encode(
                x=alt.X("magic", sort=None),
                y="NumRows",
            )
            .interactive(),
            use_container_width=True,
        )

        # Proof-of-life debug info
        pf.debug_info()


def main():
    page = LandingPage()
    page.page_content()


if __name__ == "__main__":
    main()
