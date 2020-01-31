import os
import argparse
import re
import validators
from keys import misp_auth, misp_url

curl_path = r"C:\curl-7.68.0-win64-mingw\bin" #fill where curl.exe exist!

def add_attribute(_event_id, _value, _category, _type):
    _event_id = _event_id
    _value = _value
    _category = _category
    _type = _type
    command = "curl --insecure --header \"Authorization: {0}\" --header \"Accept: application/json\" --header \"Content-Type: application/json\" -d \"{{\\\"event_id\\\":\\\"{1}\\\",\\\"value\\\":\\\"{2}\\\",\\\"category\\\":\\\"{3}\\\",\\\"type\\\":\\\"{4}\\\"}}\" {5}".format(misp_auth, _event_id, _value, _category , _type, misp_url + "attributes/add/{}".format(_event_id))
    print(command)
    os.system(command)

def check_data_character(data):    
    md5 = re.findall(r"([a-fA-F\d]{32})", data)
    sha1 = re.findall(r"([a-fA-F\d]{40})", data)
    sha256 = re.findall(r"([a-fA-F\d]{64})", data)

    if md5:
        data = [md5[0], "md5"]

    elif sha1:
        data = [sha1[0], "sha1"]

    elif sha256:
        data = [sha256[0], "sha256"]

    elif validators.url(data) == True:
        data = [data, "url"]

    else:
        data = [data, "file name"]

    return data

if __name__ == "__main__":
    IoC_file_path = "./Ioc.txt"
    
    _event_id = int(input("what's event id? "))

    f = open(IoC_file_path, "r")
    lines = f.readlines()
    for ioc in lines:
        data = check_data_character(ioc)

        if data[1] == "md5":
            _value = data[0]
            _category = "Artifacts dropped"
            _type = "md5"
        
        elif data[1] == "sha1":
            _value = data[0]
            _category = "Artifacts dropped"
            _type = "sha1"

        elif data[1] == "url":
            _value = data[0]
            _category = "Artifacts dropped"
            _type = "url"
        
        elif data[0] == "":
            continue

        else:
            _value = data[0]
            _category ="Artifacts dropped"
            _type = "filename"
        
        add_attribute(_event_id,_value,_category,_type)




