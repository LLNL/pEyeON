import vt
import os
import json

from dotenv import load_dotenv

class FileReport:
    '''
    We can define what elements we want from a file hash search
    '''
    def __init__(self, report:dict):
        self.id=report.get("id")
        self.creationdate=report.get("creation_date")
        self.firsttime=report.get("first_submission_date")
        self.lasttime=report.get("last_analysis_date")
        self.filename=report.get("meaningful_name")
        self.filesize=report.get("size")
        self.filetype=report.get("type_extension")
        self.md5=report.get("md5")
        self.sha1=report.get("sha1")
        self.sha256=report.get("sha256")
        self.reputation=report.get("reputation")#positve==good ; based on community 
        self.threatverdict=report.get("threat_verdict")
        self.magic=report.get("magic")

        #returns a list
        self.tags=report.get("tags")
        
        #returns a dict 
        # self.last_analysis_results=report.get("last_analysis_results")#provides full breakdown of each engine that was used in detection
        self.last_analysis_stats=report.get("last_analysis_stats")
        self.sigma=report.get("sigma_analysis_summary")
        self.threatdata=report.get("threat_severity")
        self.sand_box_results=report.get("sandbox_verdicts")
        self.reputation_votes=report.get("total_votes")


    def whistleblower_serilaize(self, obj):
        if isinstance(obj, vt.object.WhistleBlowerDict):
        # Convert WhistleBlowerDict to a standard dict ; loops over itself until it is done
            return {key: self.whistleblower_serilaize(value) for key, value in obj.items()}
        return obj  # Return the object as-is if it's already serializable
    
    def _safe_serialize(self, obj) -> str:
        """
        This function gives a default value to unserializable data.
        Returns json encoded string where the non-serializable bits are
        a string saying not serializable.

        Parameters:
        -----------
            obj : dict
                Object to serialize.
        """

        def default(o):
            return f"<<non-serializable: {type(o).__qualname__}>>"

        return json.dumps(obj, default=default)

    def write_results(self, filepath:str = "."):
        vs=vars(self)
        serialized={}
        os.makedirs(filepath, exist_ok=True)
        outfile = f"{os.path.join(filepath, 'VT_Results')}.{self.md5}.json"

        for key, value in vs.items():
            if isinstance(value,vt.object.WhistleBlowerDict):
                serialized[key]=self.whistleblower_serilaize(value)
            else:
                serialized[key]=value

        with open(outfile, "w") as f:
            f.write(self._safe_serialize(serialized))

load_dotenv()
API_KEY=os.getenv("VT_API")

vtclient=vt.Client(API_KEY)

file_hash="44d88612fea8a8f36de82e1278abb02f"

def search_hash(hash: str, client: vt.Client):
    with client: #context manager will handle connection close
        try:
            file_report=client.get_object(f"/files/{hash}")
            vt_file_data=FileReport(file_report)
            print(f"Successfully Retreived Report for {file_hash} - {vt_file_data.filename}")
            # print(vars(file_report)) #will return all data from VT search
            # print(vars(vt_file_data)) #returns data we specify in FileReport Class
            vt_file_data.write_results()
        except vt.error as e:
            print("Error getting VT report", e)

search_hash(file_hash, vtclient)


