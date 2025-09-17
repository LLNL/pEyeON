import unittest
import eyeon.upload
import pandas as pd
import os

from unittest.mock import patch, MagicMock
from box.box_config import BoxSettings

class TestBoxClient(unittest.TestCase):
    def setUp(self):
        self.dummy_box_settings=BoxSettings(
            BOX_CLIENT_ID="dummy ID",
            BOX_CLIENT_SECRET="notasecret",
            REDIRECT_HOST="local",
            REDIRECT_PORT=80,
            TOKEN_STORE="/token/store",
            FOLDER=12345
        )

    @patch("box.box_config.get_box_settings")
    @patch("box.box_auth.authenticate_oauth")
    def test_get_box_client(self, mock_authenticate_oauth, mock_settings):
        mock_settings.return_value=self.dummy_box_settings
        mock_client = MagicMock()
        mock_authenticate_oauth.return_value = mock_client

        client = eyeon.upload.get_box_client()

        mock_settings.assert_called_once()
        mock_authenticate_oauth.assert_called_once_with(self.dummy_box_settings)
        self.assertEqual(client, mock_client)

class TestListBoxItems(unittest.TestCase):
    def setUp(self):
        self.dummy_box_settings=BoxSettings(
            BOX_CLIENT_ID="dummy ID",
            BOX_CLIENT_SECRET="notasecret",
            REDIRECT_HOST="local",
            REDIRECT_PORT=80,
            TOKEN_STORE="/token/store",
            FOLDER=12345
        )

    @patch("eyeon.upload.get_box_client")
    @patch("eyeon.upload.box_config.get_box_settings")
    def test_list_box_items_files(self, mock_settings, mock_get_box_client):
        mock_settings.return_value = self.dummy_box_settings
        
        # Mock client and items
        mock_client = MagicMock()
        mock_folder = MagicMock()
        mock_item_file = MagicMock()
        mock_item_file.type = "file"
        mock_item_file.name = "test.txt"
        mock_item_file.id = "999"
        
        # Mock file details
        mock_user = MagicMock()
        mock_user.size = 123
        mock_user.created_at = "2023-01-01"
        mock_user.modified_at = "2023-01-02"
        mock_user.created_by.name = "Alice"
        mock_client.file.return_value.get.return_value = mock_user
        
        mock_folder.get_items.return_value = [mock_item_file]
        mock_client.folder.return_value = mock_folder
        mock_get_box_client.return_value = mock_client
        
        # Run
        df = eyeon.upload.list_box_items()
        
        # Assert DataFrame contents
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(df.iloc[0]["Filename"], "test.txt")
        self.assertEqual(df.iloc[0]["ID"], "999")
        self.assertEqual(df.iloc[0]["Size"], 123)
        self.assertEqual(df.iloc[0]["Created"], "2023-01-01")
        self.assertEqual(df.iloc[0]["Modified"], "2023-01-02")
        self.assertEqual(df.iloc[0]["Uploaded by"], "Alice")

    @patch("eyeon.upload.get_box_client")
    @patch("eyeon.upload.box_config.get_box_settings")
    def test_list_box_items_folder(self, mock_settings, mock_get_box_client):
        mock_settings.return_value = self.dummy_box_settings

       # Mock client and items
        mock_client = MagicMock()
        mock_folder = MagicMock()
        mock_item_file = MagicMock()
        mock_item_file.type = "folder"
        mock_item_file.name = "TestFolder"
        mock_item_file.id = "001"
        
        # Mock file details
        mock_user = MagicMock()
        mock_user.size = 0
        mock_user.created_at = "2023-01-01"
        mock_user.modified_at = "2023-01-02"
        mock_user.created_by.name = "Alice"
        mock_client.file.return_value.get.return_value = mock_user
        
        mock_folder.get_items.return_value = [mock_item_file]
        mock_client.folder.return_value = mock_folder
        mock_get_box_client.return_value = mock_client

        df = eyeon.upload.list_box_items()

        assert not df.empty
        assert df.iloc[0]["Filename"] == "TestFolder"
        assert df.iloc[0]["ID"] == "001"
        assert df.iloc[0]["Size"] == 0
        assert df.iloc[0]["Created"] == "2023-01-01"
        assert df.iloc[0]["Modified"] == "2023-01-02"
        assert df.iloc[0]["Uploaded by"] == "Alice"


class TestDeleteFile(unittest.TestCase):
    def setUp(self):
        self.dummy_box_settings=BoxSettings(
            BOX_CLIENT_ID="dummy ID",
            BOX_CLIENT_SECRET="notasecret",
            REDIRECT_HOST="local",
            REDIRECT_PORT=80,
            TOKEN_STORE="/token/store",
            FOLDER=12345
        )
    
    @patch("eyeon.upload.get_box_client")
    @patch("eyeon.upload.box_config.get_box_settings")
    def test_delete_file_by_id(self, mock_settings, mock_get_box_client):
        mock_settings.return_value = self.dummy_box_settings
        
        mock_client = MagicMock()
        mock_file = MagicMock()
        mock_file.name = "test.txt"
        mock_client.file.return_value.get.return_value = mock_file
        mock_get_box_client.return_value = mock_client
        
        with patch.object(mock_file, "delete") as mock_delete:
            eyeon.upload.delete_file("123")
            mock_client.file.assert_called_with(123)
            mock_delete.assert_called_once()
    
    @patch("eyeon.upload.get_box_client")
    @patch("eyeon.upload.box_config.get_box_settings")
    def test_delete_file_by_name_found(self, mock_settings, mock_get_box_client):
        mock_settings.return_value = self.dummy_box_settings
        
        mock_client = MagicMock()
        mock_folder = MagicMock()
        mock_item = MagicMock()
        mock_item.type = "file"
        mock_item.name = "foo.txt"
        mock_item.id = "456"
        mock_folder.get_items.return_value = [mock_item]
        mock_client.folder.return_value = mock_folder
        mock_get_box_client.return_value = mock_client
        
        with patch.object(mock_item, "delete") as mock_delete:
            eyeon.upload.delete_file("foo.txt")
            mock_delete.assert_called_once()
    
    @patch("eyeon.upload.get_box_client")
    @patch("eyeon.upload.box_config.get_box_settings")
    def test_delete_file_by_name_not_found(self, mock_settings, mock_get_box_client):
        mock_settings.return_value = self.dummy_box_settings
        
        mock_client = MagicMock()
        mock_folder = MagicMock()

        # No items matching
        mock_folder.get_items.return_value = []
        mock_client.folder.return_value = mock_folder
        mock_get_box_client.return_value = mock_client
        
        # Should not raise, just print
        with patch("builtins.print") as mock_print:
            eyeon.upload.delete_file("doesnotexist.txt")
            mock_print.assert_any_call("File named 'doesnotexist.txt' not found in folder.")
        

    @patch("eyeon.upload.get_box_client")
    @patch("eyeon.upload.box_config.get_box_settings")
    def test_delete_file_by_id_not_found(self, mock_settings, mock_get_box_client):
        mock_settings.return_value = self.dummy_box_settings

        # Setup mock client and exception on .get()
        mock_client = MagicMock()
        mock_file = MagicMock()

        mock_file.get.side_effect = Exception("Not Found")
        mock_client.file.return_value = mock_file
        mock_get_box_client.return_value = mock_client

        with patch("builtins.print") as mock_print:
            eyeon.upload.delete_file("123456")
            mock_print.assert_any_call("File with ID 123456 not found or could not be deleted: Not Found")

class TestUpload(unittest.TestCase):
    @patch("eyeon.upload.get_box_client")
    @patch("eyeon.upload.box_config.get_box_settings")
    def test_upload_allowed_extension(self, mock_settings, mock_get_box_client):
        settings = MagicMock()
        settings.FOLDER = 12345
        mock_settings.return_value = settings
        
        mock_client = MagicMock()
        mock_folder = MagicMock()
        mock_uploaded_file = MagicMock()
        mock_uploaded_file.id = "101"
        mock_folder.upload.return_value = mock_uploaded_file
        mock_client.folder.return_value = mock_folder
        mock_get_box_client.return_value = mock_client
        
        with patch("os.path.splitext", return_value=("foo", ".zip")):
            eyeon.upload.upload("foo.zip")
            mock_folder.upload.assert_called_with("foo.zip")
    
    def test_upload_disallowed_extension(self):
        with patch("os.path.splitext", return_value=("foo", ".txt")):
            # Should just print a message and return
            eyeon.upload.upload("foo.txt")
