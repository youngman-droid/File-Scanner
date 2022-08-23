import hashlib
import requests
import sys
import time
# api key and urls
API_KEY = ""
url = "https://api.metadefender.com/v4/"
# constants
BLOCK_SIZE = 8192

# Function calculate hash of a file
def hash_func(filename):
    hash_sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        block = f.read(BLOCK_SIZE)
        while len(block) > 0:
            hash_sha256.update(block)
            block = f.read(BLOCK_SIZE)
    return (hash_sha256.hexdigest())


# function to check if hash exists already:
def hash_check(hash, filename):
    try:
        response = requests.request(
            "GET", url + "hash/" + hash, headers={"apikey": API_KEY, filename:filename})
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    if response.status_code == 200:
        print_results(response)
        return True
    else:
        return False

# function to print scan results


def print_results(result):
    scanresults = result.json()
    print("filename: ", scanresults["file_info"]["display_name"])
    print("overall_status: ", scanresults["scan_results"]["scan_all_result_a"])
    scan_details = scanresults["scan_results"]["scan_details"]
    for details in scan_details:
        print("engine: ", details)
        print("threat_found: ", scan_details[details]["threat_found"] or "CLEAN")
        print("scan_result: ", scan_details[details]["scan_result_i"])
        print("def_time: ", scan_details[details]["def_time"])

# function to upload file if hash not found and returns the id of the file


def upload_file(filename):
    try:
        response = requests.request("POST", url + "file", headers={"apikey": API_KEY,"Content-Type": "application/octet-stream","filename": filename }, data=open(filename, "rb"))
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    if response.status_code == 200:
        return (response.json()["data_id"])
    else:    
        print("Error: Upload unsuccessful, bad request", file=sys.stderr)
        exit(1)
#repeatedly pulls on the id until its complete then prints the results

def pull_id(id):
    while True:
        try:    
            response = requests.request(
                "GET", url + "file/" + str(id), headers={"apikey": API_KEY, filename: filename})
        except requests.exceptions.RequestException as e:
            raise SystemExit(e)
        if response.status_code == 200:
            responsejson = response.json()
            if responsejson["scan_results"]["progress_percentage"] == 100:
                break
            else:
                time.sleep(5)
                print("Progress:" + str(responsejson["scan_results"]["progress_percentage"]) +"%")
        else:
            print("Connection error while pulling", file = sys.stderr)
            exit(1)
    print_results(response)
if __name__ == "__main__":
    # check for proper usage
    if len(sys.argv) != 2:
        print("Usage: python3 upload_file.py SampleFile.txt", file=sys.stderr)
        exit(1)
    filename = sys.argv[1]
    hash = hash_func(filename)
    ishash = hash_check(hash, filename)
    #upload the file if not hash and get the id
    if not ishash:
        data_id = upload_file(filename)
        #pull on data id and retrieve results
        pull_id(data_id)
