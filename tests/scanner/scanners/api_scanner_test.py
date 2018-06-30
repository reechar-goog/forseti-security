# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Blacklist Scanner Test"""

import mock
from mock import patch, Mock
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import instance
from google.cloud.forseti.scanner.scanners import api_scanner
from google.cloud.forseti.scanner.audit import blacklist_rules_engine as bre

from tests.scanner.test_data import fake_blacklist_scanner_data as fbsd
from tests.unittest_utils import get_datafile_path

class APIScannerTest(ForsetiTestCase):

    @patch('google.cloud.forseti.scanner.audit.' + \
           'blacklist_rules_engine.urllib2.urlopen')
    def test_dick(self, mock_urlopen):
        a = Mock()
        a.read.side_effect = [fbsd.FAKE_BLACKLIST_SOURCE_1]
        mock_urlopen.return_value = a

        richard = "richard"
        dick = "richard"
        self.assertEqual(richard, dick)


if __name__ == '__main__':
    unittest.main()
