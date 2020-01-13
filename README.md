# CVE Lookup

CVE Lookup is a Django web app to search CVEs from the National 
Vulnerability Database. 

Quick start
-----------

1. Download or Clone this repository

2. Install dependencies from requirements.txt

    $ pip install -r requirements.txt

3. Start the development server and visit http://127.0.0.1:8000/

4. The app uses SQLLite database *cve_db* present in the root

5. You can use other database like Postgresql by simply changing the settings.py. Don't forget
to run manage.py migrate command in case you do it!

6. A custom management command is provided to pull CVEs from https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
You can pass the ZIP file URL to the command 
    
    Example
     
    $ python manage.py loadcve -u https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip