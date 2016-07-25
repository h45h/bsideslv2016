from datetime import datetime
from io import RawIOBase, BufferedReader
from json import dumps
from logging import info, basicConfig, INFO
from traceback import print_exc

from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from splunklib import client, results

from better_splunk import BetterSplunk

try:
    from xml.etree.ElementTree import ParseError
except ImportError, e:
    from xml.parsers.expat import ExpatError as ParseError


disable_warnings(InsecureRequestWarning)
basicConfig(level=INFO)


class ResponseReaderWrapper(RawIOBase):
    """This is from the internet! It's a wrapper to increase io speed of result parsing...
    From testing, it was not a huge help."""

    def __init__(self, responseReader):
        self.responseReader = responseReader

    def readable(self):
        return True

    def close(self):
        self.responseReader.close()

    def read(self, n):
        return self.responseReader.read(n)

    def readinto(self, b):
        sz = len(b)
        data = self.responseReader.read(sz)
        for idx, ch in enumerate(data):
            b[idx] = ch

        return len(data)


def get_service(username, password, port, host):
    """
    Convenience function for connecting to the traditional API client.
    :param username:
    :param password:
    :return:
    """
    try:
        return client.connect(
                host=host,
                port=port,
                username=username,
                password=password)
    except:
        print "Connection failed. Check your VPN or credentials. More details: {0}".format(print_exc())
        return False


def api_export_query(service, query, out_file="api_export_query.json"):
    kwargs_normalsearch = {"search_mode": "normal",
                           "count": 0}
    _results = service.jobs.export(query, **kwargs_normalsearch)

    with open(out_file,'w') as f_out:
        # Get the search results and display them
        reader = results.ResultsReader(BufferedReader(ResponseReaderWrapper(_results)))
        for result in reader:
            if isinstance(result, dict):
                f_out.write(dumps(result) + '\n')
            elif isinstance(result, results.Message):
                # Diagnostic messages may be returned in the results
                print "Message: %s" % result



def api_blocking_query(service, query, out_file="api_blocking_query.json"):
    kwargs_normalsearch = {"exec_mode": "blocking",
                           "count": 0}
    job = service.jobs.create(query, **kwargs_normalsearch)

    # Splunk doesn't like to give the whole result
    # set from the job, so we have to paginate.
    # This seems to change for each version in 6.x, so sometimes you get 100 results by default
    # Sometimes you get the max.

    result_count = job["resultCount"]
    offset = 0
    count = 50000  # 50k is the absolute max it'll do...because, splunk.
    kwargs_container = []

    while offset < int(result_count):
        kwargs_paginate = {"count": count,
                           "offset": offset}
        # Not expressly necessary, just setting up a container for the pagination args
        kwargs_container.append(kwargs_paginate)
        offset += count

    with open(out_file,'w') as f_out:
        # Get the search results and display them
        for kwargs_paginate in kwargs_container:
            blocksearch_results = job.results(**kwargs_paginate)
            for result in results.ResultsReader(BufferedReader(ResponseReaderWrapper(blocksearch_results))):
                f_out.write(dumps(result) + '\n')
    job.cancel()

# #### CONSTANTS ####
HOST = "your splunk instance"
DIRECT_DOWNLOAD_PORT = 8000  # This method uses 8000 instead of 8089 by default
API_PORT = 8089
USERNAME= 'username'
PASSWORD = 'password'
QUERY = r'search index=_internal sourcetype=splunkd_ui_access user={0}'.format(USERNAME)

_service = get_service(USERNAME, PASSWORD, API_PORT, HOST)
if _service:

##### TEST 1 #####
# Test with the direct download method
    info("Running test 1")
    b = BetterSplunk(host=HOST, port=DIRECT_DOWNLOAD_PORT, username=USERNAME, password=PASSWORD)
    b.connect()
    b.login()
    start_1 = datetime.now()
    b.make_query(_service, QUERY, None)
    end_1 = datetime.now()

##### TEST 2 #####
# Now test with the API
    info("Running test 2")
    start_2 = datetime.now()
    api_blocking_query(_service, QUERY)
    end_2 = datetime.now()

##### TEST 3 #####
# Now test with the export api
    info("Running test 3")
    start_3 = datetime.now()
    api_export_query(_service, QUERY)
    end_3 = datetime.now()

    info('first test took: {0}'.format((end_1-start_1).total_seconds()))
    info('second test took: {0}'.format((end_2-start_2).total_seconds()))
    info('third test took: {0}'.format((end_3-start_3).total_seconds()))


# SAMPLE RUN RESULTS
# INFO:root:Result count for query: 111356
# INFO:root:first test took: 72.060835
# INFO:root:second test took: 343.893909
# INFO:root:third test took: 332.176072