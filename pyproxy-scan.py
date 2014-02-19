#!/usr/bin/env python
"""
Very simple HTTP proxy to perform anti-virus scan on the fly using clamav.

This is an experiment, use it at your own risk (specially because the
limitations of stream scanning in clamav).


Copyright (C) 2014 by Memset Ltd. http://www.memset.com/

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import cherryproxy
from pyclamd import pyclamd

# you may need to change this
CLAMD_SOCKET = '/var/run/clamav/clamd.ctl'

class CherryProxyAV(cherryproxy.CherryProxy):

    def __init__(self, *args, **kwargs):
        super(CherryProxyAV, self).__init__(*args, **kwargs)

        try:
            self.av = pyclamd.ClamdUnixSocket(CLAMD_SOCKET)
            self.av.ping()
        except pyclamd.ConnectionError:
            raise ValueError('Could not connect to clamd server is %s' % CLAMD_SOCKET)

    def filter_response(self):
        result = self.av.scan_stream(self.resp.data)
        if result:
            msg = 'Response blocked due to potential threat'
            body = '%s\n\n%r' % (msg, result)
            self.req.log.warning("%r" % msg)
            self.set_response_forbidden(reason=msg, data=body)

if __name__ == "__main__":
    cherryproxy.main(CherryProxyAV)

