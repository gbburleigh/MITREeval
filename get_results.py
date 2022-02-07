import urllib.request, os
from ref import StatsRef
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
if not os.path.exists(os.getcwd() + '/json'):
    os.makedirs(os.getcwd() + '/json')
participants = StatsRef().__participants__()
for p in participants:
    try:
        urllib.request.urlretrieve(f'https://attackevals.mitre-engenuity.org/downloadable_JSON/{p}_Results.json', os.getcwd() + f'/json/{p}_Results.json')
    except:
        pass
    assert(os.path.exists(os.getcwd() + f'/json/{p}_Results.json'))