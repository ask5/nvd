# from io import BytesIO
# from zipfile import ZipFile
# import urllib.request
# import json
#
# url = urllib.request.urlopen("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip")
#
# with ZipFile(BytesIO(url.read())) as my_zip_file:
#     for contained_file in my_zip_file.namelist():
#         content = my_zip_file.open(contained_file).read()
#         data = json.loads(content)
#         for c in data['CVE_Items']:
#             print(c['cve']['CVE_data_meta']['ID'])


import json

with open('jsons/nvdcve-1.1-modified') as json_file:
    data = json.load(json_file)

    # for c in data['CVE_Items']:
    #     if 'cpe_match' in c['configurations']['nodes'][0]:
    #     cve = len()
    #     print(cve)

    # for d in c['cve']['description']['description_data']:
    #    print(d['value'])

    # for c in data['CVE_Items']:
    #     print(c['cve']['CVE_data_meta']['ID'])
    #
    #     #for d in c['cve']['description']['description_data']:
    #     #    print(d['value'])
    #
    #     if 'baseMetricV2' in c['impact']:
    #         print("CVSS V2 base score: "+ str(c['impact']['baseMetricV2']['cvssV2']['baseScore']))
    #         print("CVSS V2 severity: " + c['impact']['baseMetricV2']['severity'])
    #
    #     if 'baseMetricV3' in c['impact']:
    #         print("CVSS V3 base score: "+ str(c['impact']['baseMetricV3']['cvssV3']['baseScore']))
    #         print("CVSS V3 severity: " + c['impact']['baseMetricV3']['cvssV3']['baseSeverity'])
