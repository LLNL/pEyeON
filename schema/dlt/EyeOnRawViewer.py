# Requirements are: streamlit, duckdb

import streamlit as st
import duckdb

st.title("Binary Metadata Viewer")

try:
    # Compact settings in collapsible section
    with st.sidebar:
        st.subheader("Database")
        db_path = st.text_input("Database path:", "eyeon_metadata.duckdb")

        con = duckdb.connect(db_path, read_only=True)
        schema_list = [s[0] for s in con.execute(
            "SELECT distinct schema_name FROM information_schema.schemata order by all"
        ).fetchall()]
    
        # Schema selection inside the same expander context
        cur_schema = st.selectbox("Schema to use", schema_list)
    
        if cur_schema is not None:
            con.sql(f"use {cur_schema}")
            table_list = [s[0] for s in con.execute("show tables").fetchall()]
            with st.expander("Tables"):
                st.table(table_list)
            
            if "raw_obs" not in table_list:
                st.warning("Pick a valid schema. This one doesn't have the RAW_OBS table")
                st.stop()

            # Display some stats about the database
            # Go steal code from the old streamlit app...
            st.markdown("_Cool Stats Here_")
            
    # Main UI - prominently displayed
    filter_text = st.text_input(
        "🔍 Filter files:", 
        placeholder="Use % or * for wildcard (case insensitive)"
    )
    
    # Apply filter
    if filter_text:
        files_df = con.execute(
            "SELECT uuid, filename, bytecount FROM raw_obs WHERE filename ILIKE ? ORDER BY filename",
            [f"%{filter_text.replace('*', '%') }%"]
        ).df()
    else:
        files_df = con.execute(
            "SELECT uuid, filename, bytecount FROM raw_obs ORDER BY filename"
        ).df()
    
    # File selector
    if len(files_df) > 0:
        selected_file = st.selectbox(
            "📄 Select a file:",
            files_df['filename'].tolist(),
            format_func=lambda x: x if x else "(unnamed)"
        )
        
        # Get the UUID for selected file
        uuid = files_df[files_df['filename'] == selected_file]['uuid'].iloc[0]
        
        st.subheader("File Info")
        file_info = files_df[files_df['uuid'] == uuid]
        st.dataframe(file_info, use_container_width=True)
        
        # Get metadata tables dynamically
        metadata_tables = [s[0] for s in con.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_name LIKE 'metadata_%' AND NOT contains(table_name,'__') "
            "ORDER BY table_name"
        ).fetchall()]
        
        for table in metadata_tables:
            result = con.execute(
                f"SELECT * FROM {table} WHERE uuid = ?",
                [uuid]
            ).df()
            
            if len(result) > 0:
                st.subheader(table.replace('metadata_', '').upper())
                st.dataframe(result, use_container_width=True)
                
                # Find any nested tables
                nested_tables = [s[0] for s in con.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_name LIKE ? AND contains(table_name,'__') "
                    "ORDER BY table_name",
                    [f"{table}__%"]
                ).fetchall()]
                
                for nested_table in nested_tables:
                    nested_result = con.execute(
                        f"SELECT * FROM {nested_table} WHERE _dlt_parent_id = ?",
                        [result['_dlt_id'].iloc[0]]
                    ).df()
                    
                    if len(nested_result) > 0:
                        st.subheader(nested_table.replace('metadata_', '').upper())
                        st.dataframe(nested_result, use_container_width=True)
    else:
        st.warning("No files found in database")
        
except Exception as e:
    st.error(f"Error: {e}")