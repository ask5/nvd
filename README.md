# CVE Lookup

CVE Lookup is a Django web app to search CVEs from the National 
Vulnerability Database.  

## Requirements

* Python 3.6 or greater
* virtualenv

## Installation

Clone the repository

    git clone https://github.com/ask5/nvd.git

Create virtual environment and install dependencies from requirements.txt

    virtualenv nvd
    source nvd/bin/activate (nvd/Scripts/activate for Windows)
    pip install -r nvd/requirements.txt

Run local server

    cd nvd
    python manage.py runserver
    
Check if the Site is up

    http://127.0.0.1:8000/app/
    
## Database    

The app is configured to use SQLLite database called *cve_db* available at the root

To use PostgreSQL:

    1. Change settings.py
    
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.postgresql',
                'NAME': 'mydatabase',
                'USER': 'mydatabaseuser',
                'PASSWORD': 'mypassword',
                'HOST': '127.0.0.1',
                'PORT': '5432',
            }
        }

    2. Run migration
    
        python manage.py migrate

## Pulling CVEs from NVD website    

A custom management command is provided to pull CVEs from https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

Command handler
    
    app/management/commands/loadcve.py

Parser Class

    app/lib/nvd_cve.py
    
Usage

    python manage.py loadcve --help    
    
    usage: manage.py loadcve [-h] [-u URL] [-f FILE] [-l] [--version]
                         [-v {0,1,2,3}] [--settings SETTINGS]
                         [--pythonpath PYTHONPATH] [--traceback] [--no-color]
                         [--force-color] [--skip-checks]
    Imports a CVE File
    
    optional arguments:
      -h, --help            show this help message and exit
      -u URL, --url URL     URL of the CVE JSON ZIP file hosted on the website
      -f FILE, --file FILE  Local file path to CVE Json file
      -l, --log             Show log
      --version             show program's version number and exit
      -v {0,1,2,3}, --verbosity {0,1,2,3}
                            Verbosity level; 0=minimal output, 1=normal output,
                            2=verbose output, 3=very verbose output
      --settings SETTINGS   The Python path to a settings module, e.g.
                            "myproject.settings.main". If this isn't provided, the
                            DJANGO_SETTINGS_MODULE environment variable will be
                            used.
      --pythonpath PYTHONPATH
                            A directory to add to the Python path, e.g.
                            "/home/djangoprojects/myproject".
      --traceback           Raise on CommandError exceptions
      --no-color            Don't colorize the command output.
      --force-color         Force colorization of the command output.
      --skip-checks         Skip system checks.
    
Example

    $ python manage.py loadcve -u https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip