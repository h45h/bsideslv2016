#!/usr/bin/env python

from json import loads
from logging import info, basicConfig, INFO
from traceback import print_exc
from urllib import urlencode

from bs4 import BeautifulSoup
from requests import get as requests_get
from requests import post as requests_post
from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from splunklib.binding import _NoAuthenticationToken, Context, HTTPError, AuthenticationError

try:
    from xml.etree.ElementTree import ParseError
except ImportError, e:
    from xml.parsers.expat import ExpatError as ParseError

disable_warnings(InsecureRequestWarning)
basicConfig(level=INFO)


class BetterSplunk(Context):
    """
    Wrapper class for the splunk sdk Context class to establish login and stream results.
    """
    def __init__(self, **kwargs):
        super(BetterSplunk, self).__init__(**kwargs)
        self.__dict__.update(kwargs)
        self._splunk_version = None

    def download_job_sid(self, sid, mode='json', filename=None):
        """
        Wrapper for streaming results to a file instead of through sockets with the API.
            :param sid: sid of job
            :param mode: json, csv, or xml
            :return: local filename, False if failure
        """

        # Only tested on 6.3, may need to mod this
        job_sid_url = 'https://{0}/en-US/api/search/jobs/{1}/results?isDownload=true&' \
                      'timeFormat=%25FT%25T.%25Q%25%3Az&maxLines=0&count=0&filename=&outputMode={2}' \
                      '&spl_ctrl-limit=unlimited&spl_ctrl-count=50000'.format(self.host, sid, mode)

        if not filename:
            filename= '{0}.{1}'.format(sid, mode)
        cookie_builder = {}
        for l in self._auth_headers:
            for x in l[1].split('; '):
                q = x.split('=')
                cookie_builder[q[0]] = q[1]
        r = requests_get(job_sid_url, stream=True, cookies=cookie_builder, verify=False)
        cnt = 0
        with open(filename, 'wb') as f:
            # I have the bandwidth to do this size, you may not.
            for chunk in r.iter_content(chunk_size=1024*1024*1024):
                if chunk:
                    f.write(chunk)
                cnt += 1
                if cnt % 1000 == 0:
                    # Call control occasionally to keep the export stream alive
                    requests_post(r'https://{0}/en-US/splunkd/__raw/services/search/jobs/{1}/control'
                                  .format(self.host, sid), data={
                                        'output_mode': mode,
                                        'action': 'touch'
                                    }, cookies=cookie_builder, verify=False)
        return filename

    def make_query(self, service, query, output_filename=None, mode='json'):
        job = None
        try:
            kwargs_normalsearch = {"exec_mode": "blocking",
                                   "count": 0}
            job = service.jobs.create(query, **kwargs_normalsearch)

            # I like to set a long timeout here, we will cancel the job after we export the results
            # The reason behind this is Splunk keeps the job around only for a few minutes by default,
            # and in some cases would cancel for us, even if results are still being streamed.

            job.set_ttl(12*60*60)

            result_count = job["resultCount"]
            info("Result count for query: {0}".format(result_count))
            sid = job.sid
            if not output_filename:
                output_filename = '{0}.{1}'.format(sid, mode)
            self.download_job_sid(sid,mode,output_filename)
            job.cancel()

        except:
            print print_exc()
            if job:
                job.cancel()

    def login(self):
        """
        Overriding login to grab token and cookie to use later
        :return:
        """

        if self.has_cookies() and \
                (not self.username and not self.password):
            # If we were passed session cookie(s), but no username or
            # password, then login is a nop, since we're automatically
            # logged in.
            return

        if self.token is not _NoAuthenticationToken and \
                (not self.username and not self.password):
            # If we were passed a session token, but no username or
            # password, then login is a nop, since we're automatically
            # logged in.
            return

        # Only try to get a token and updated cookie if username & password are specified
        # Load the login page, get the cval hidden input
        resp = self.http.get(self.authority + self._abspath("/en-US/account/login"))
        b = resp.body.read()
        soup = BeautifulSoup(b, 'html.parser')
        t = soup.findAll('script', attrs={'id':'splunkd-partials'})

        # Must submit this cval hidden input with the initial post
        cval = loads(t[0].contents[0])[u'/services/session']['entry'][0]['content']['cval']
        try:

            self.http.request(self.authority + self._abspath("/en-US/account/login"),
                             {'method': 'POST',
                             'headers': self._auth_headers,
                             'body': urlencode(
                                 {'cval':cval,'username':self.username,
                                 'password':self.password,'return_to':r'/en=US/'})})

            return self
        except HTTPError as he:
            if he.status == 401:
                raise AuthenticationError("Login failed.", he)
            else:
                raise


