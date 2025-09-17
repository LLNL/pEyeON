from box import box_auth, box_config
from boxsdk import Client

import pandas as pd
import os

def get_box_client() -> Client:
    '''
    authenticate with the box service
    '''
    settings=box_config.get_box_settings()
    client = box_auth.authenticate_oauth(settings)
    return client


def list_box_items():
    settings=box_config.get_box_settings()
    client = get_box_client()

    data = pd.DataFrame(
        columns=["Filename", "ID", "Size", "Created", "Modified", "Uploaded by"]
    )

    for item in client.folder(settings.FOLDER).get_items(limit=1000):
        # Get extra fields beyond the minimal.
        user = client.file(item.id).get(
            fields=["created_by", "size", "created_at", "modified_at"]
        )
        if item.type == "file":
            new_data = {
                "Filename": item.name,
                "ID": item.id,
                "Size": user.size,
                "Created": user.created_at,
                "Modified": user.modified_at,
                "Uploaded by": user.created_by.name,
            }
            data = pd.concat([data, pd.DataFrame([new_data])], ignore_index=True)

        elif item.type == "folder":
            new_data = {
                "Filename": item.name,
                "ID": item.id,
                "Size": user.size,
                "Created": user.created_at,
                "Modified": user.modified_at,
                "Uploaded by": user.created_by.name,
            }
            data = pd.concat([data, pd.DataFrame([new_data])], ignore_index=True)
    print(data)
    return data

def delete_file(file:str):
    '''
    delete target file by name or ID
    '''
    settings=box_config.get_box_settings()
    client = get_box_client()
    

    if file.isdigit():
        #if the file is all digit assume they are trying to delete based on item id
        file_id=int(file)
        try:
            box_file = client.file(file_id).get()
            print(f"Deleting file '{box_file.name}' (ID: {file_id})")
            box_file.delete()
        except Exception as e:
            print(f"File with ID {file_id} not found or could not be deleted: {e}")
        return
    

    elif not file.isdigit():
        folder=client.folder(settings.FOLDER)
        file_name=file.split('/')[-1] #need to split as file is path with path
        # Delete existing file with same name
        found = False
        for item in folder.get_items(limit=1000):
            if item.type == 'file' and item.name == file_name:
                print(f"Deleting file '{file_name}' (ID: {item.id})")
                item.delete()
                found = True
                break
        if not found:
            print(f"File named '{file_name}' not found in folder.")
        return

    else:
        print("Invalid input type. Must be file name or ID")
        return

def upload(file: str):
    '''
    upload target file
    '''
    allowed_ext=[".zip", ".tar", ".gz"]

    _, ext = os.path.splitext(file)

    if ext.lower() in allowed_ext:
        settings=box_config.get_box_settings()
        client = get_box_client()

        new_file = client.folder(settings.FOLDER).upload(file)
        print(f"Uploaded {file!r} as file ID {new_file.id}")
    
    else:
        print(f"please compress into one of the following formats: \n{allowed_ext}")
        return

#add zip / tar feature
