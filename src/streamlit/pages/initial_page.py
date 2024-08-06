import common.page_frags as pf
from pages._base_page import BasePageLayout
from pages.pages import app_pages
from common.utils import sidebar_config
from utils.config import settings
import streamlit as st
import common.dqautil as du


class LandingPage(BasePageLayout):
    def __init__(self):
        super().__init__()

    def page_content(self):
        st.set_page_config(
            page_icon=settings.app.logo, page_title="Observations Summary", layout="wide"
        )
        sidebar_config(app_pages())
        st.header("Summary info for current Observations")
        pf.summary()

        st.markdown("Observations Clustered by Time")
        obs_times_df = du.getdatafor(du.getcon(), "observation_times")
        st.bar_chart(obs_times_df, x="ObsTime", y="NumRows")
        st.dataframe(obs_times_df)

        # Proof-of-life debug info
        pf.debug_info()


def main():
    page = LandingPage()
    page.page_content()


if __name__ == "__main__":
    main()
