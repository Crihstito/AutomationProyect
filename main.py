from flask import Flask, request
from modules import reading
from webexteamssdk import WebexTeamsAPI
import json
import requests
import csv

app = Flask(__name__)

token = 'N2I0YTNlY2QtYmMzNS00ZjdhLTliMzYtODM3M2U2ZjMyY2E1MWVmMzBjOGEtMGE2_PF84_1eb65fdf-9643-417f-9974-ad72cae0e10f'

headers = {
    'Authorization': 'Bearer ' + token
}

api = WebexTeamsAPI(access_token=token)

@app.route("/", methods=["POST"])
def hook():
    data = json.loads(request.data)
    files = data['data']['files']
    
    for file_url in files:
        response = requests.get(file_url, headers=headers)

    if response.status_code == 200:
        #CSV RECUPERADO
        #print(response.text)
        csv_text = response.text
        _type = response.headers['Content-Type']
        if _type == 'text/csv':
            csv_data = csv.reader(csv_text.splitlines())
            output_file = "output.csv"
            with open(output_file, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerows(csv_data)
            reading.device_information(output_file)
            reading.proc_memory()
            reading.bug_information()
            reading.psirt_information(data, api)
    return ""

if __name__ == "__main__":
    app.run()

