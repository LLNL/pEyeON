
import duckdb
import json
import os
from importlib_resources import files


class DatabaseHandler:
    """
    Class to create database and load json

    Parameters:
    -----------
        filename (str): Path to database file.

    """
    def __init__(self, filename: str):
        self.database_name = filename

    def instantiate_database(self, json_file: str) -> None:
        con = duckdb.connect(self.database_name)

        # initialize following schema
        con.sql(f"create table raw_pf as select * from read_json('{json_file}', union_by_name=true);")

        # create all of the views using eyeon-ddl.sql
        con.sql(files('eyeon.database').joinpath('eyeon-ddl.sql').read_text())
        con.close()

    def import_json(self, json_file: str) -> None:
        """
        Function to add json_files to the database.
        Creates the database first if necessary
        Parameters:
        -----------
            json_file (str): Name of json file to be imported

        """
        if not os.path.exists(self.database_name):
            self.instantiate_database(json_file)
        else:
            con = duckdb.connect(self.database_name)
            con.sql(f"copy raw_pf from read_json('{json_file}', union_by_name=true);")
            con.close()

