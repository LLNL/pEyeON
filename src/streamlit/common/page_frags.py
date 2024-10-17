import common.dqautil as du
import streamlit as st
from utils.config import settings


def summary():
    # Main page containers/columns
    summary = st.container(border=True)
    col1, col2, col3 = st.columns(3)

    if du.getcon() is not None:
        # High level stats: hosts, data range
        with summary:
            with col1:
                # Yikes! Not sure this join is the simplest way, but it works.
                st.markdown(
                    f"""Observations \n#### {'/'.
                        join(map(str,du.get(du.getcon(), 'observation_count')))}"""
                )

            with col2:
                #                st.markdown(f"Hosts \n#### {du.get(du.getcon(),'host_count')[0]}")
                st.markdown("~something here~")
            with col3:
                (min, max) = du.get(du.getcon(), "raw_data_range")
                st.markdown(f"Data Range \n#### {min} - {max}")
        st.markdown(f"_Current db: {st.session_state.filename}_")


def debug_info():
    st.markdown(f"dataset path is still set to: {settings.datasets.dataset_path}")
    try:
        from streamlit.common.dqautil import Dataset

        st.markdown(f"successfully imported from common util! ({type(Dataset)})")
    except Exception as err:
        st.markdown("unable to import from common util!!")
        st.markdown(err)
