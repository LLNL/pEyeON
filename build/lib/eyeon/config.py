import configparser
import os


def ConfigRead(file: str) -> dict:
    configparse_odj = configparser.ConfigParser()
    # dir_path=os.getcwd()+"/"
    # config_file_path=dir_path+file
    baseFileName = os.path.basename(file)

    configparse_odj.read(file)
    config_data = {}
    config_data["default_filename"] = baseFileName
    # itereate through conf sections
    for section in configparse_odj.sections():
        # print(f"Section: {section}")
        section_data = {}

        # iterate through keys / values and store them in a dict
        for key in configparse_odj[section]:
            value = configparse_odj[section][key]
            section_data[key] = value
            # print(f"    Key: {key} = Value: {value}")

        config_data[section] = section_data

    return config_data
