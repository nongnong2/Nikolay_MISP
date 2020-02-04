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
    IP = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", data)
    Email = re.findall(r"\b([a-z][_a-z0-9-.]+@[a-z0-9-]+\.[a-z]+)\b", data)
    CVE = re.findall(r"\b(CVE\-[0-9]{4}\-[0-9]{4,6})\b", data)
    Filename = re.findall(r"\b([A-Za-z0-9-_\.]+\.(exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))\b", data)


    try:
        if data.replace('\n','') == md5[0]:
            data = [md5[0], "md5"]

        elif data.replace('\n','') == sha1[0]:
            data = [sha1[0], "sha1"]

        elif data.replace('\n','') == sha256[0]:
            data = [sha256[0], "sha256"]

        elif data.replace('\n', '') == IP[0]:
            data = [IP[0], "ip-src"]

        elif data.replace('\n', '') == Email[0]:
            data = [Email[0], "email-src"]
        
        elif data.replace('\n', '') == CVE[0]:
            data = [CVE[0], "vulnerability"]
        
        elif data.replace('\n', '') == Filename[0]:
            data = [Filename[0], "filename"]

    except:
        if validators.url(data.replace('[.]','.')) == True:
            data = [data.replace('\n',''), "url"]

        else:
            pass

    return data

if __name__ == "__main__":
    IoC_file_path = "./IoC_kimsuki.txt"
    
    _event_id = int(input("what's event id? "))

    f = open(IoC_file_path, "r")
    lines = f.readlines()
    for ioc in lines:
        data = check_data_character(ioc)
        try:
            if data[1] == "md5":
                _value = data[0]
                _category = "Artifacts dropped"
                _type = "md5"

            elif data[1] == "sha1":
                _value = data[0]
                _category = "Artifacts dropped"
                _type = "sha1"

            elif data[1] == "sha256":
                _value = data[0]
                _category = "Artifacts dropped"
                _type = "sha256"       

            elif data[1] == "url":
                _value = data[0]
                _category = "Network activity"
                _type = "url"

            elif data[1] == "ip-src":
                _value = data[0]
                _category = "Network activity"
                _type = "ip-src"

            elif data[1] == "email-src":
                _value = data[0]
                _category = "Network activity"
                _type = "email-src"

            elif data[1] == "vulnerability":
                _value = data[0]
                _category = "Artifacts dropped"
                _type = "vulnerability"

            elif data[1] == "filename":
                _value = data[0]
                _category = "Artifacts dropped"
                _type = "filename"

            elif data[0] == "":
                pass

            else:
                continue
        except:
            continue
        
        add_attribute(_event_id,_value,_category,_type)




