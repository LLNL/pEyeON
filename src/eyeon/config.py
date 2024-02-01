import configparser
import os
import json


def ConfigRead(file:str) -> dict:
    configparse_odj= configparser.ConfigParser()
    dir_path=os.getcwd()+"/"

    config_file_path=dir_path+file
    baseFileName=os.path.basename(config_file_path)

    configparse_odj.read(config_file_path)

    config_data={}

    #itereate through conf sections
    for section in configparse_odj.sections():
        # print(f"Section: {section}")
        section_data={}

        #iterate through keys / values and store them in a dict
        for key in configparse_odj[section]:
            value=configparse_odj[section][key]
            section_data[key]=value
            # print(f"    Key: {key} = Value: {value}")
        
        config_data[section]=section_data

    Config_Info={baseFileName:config_data}
    json_data=json.dumps(Config_Info, indent=2)
    print(json_data)