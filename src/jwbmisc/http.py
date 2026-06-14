# Source - https://stackoverflow.com/a/58055668
# Posted by Zhe, modified by community. See post 'Timeline' for change history
# Retrieved 2026-06-14, License - CC BY-SA 4.0

import requests as rq


class BearerAuth(rq.auth.AuthBase):
    """auth=BearerAuth('s3cr3t')"""

    token: str

    def __init__(self, token):
        super().__init__()
        self.token = token

    def __call__(self, req):
        req.headers["Authorization"] = "Bearer " + self.token
        return req
