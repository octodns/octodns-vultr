#
#
#

from itertools import chain, repeat
from os.path import dirname, join
from unittest import TestCase
from unittest.mock import Mock, call

from requests import HTTPError
from requests_mock import ANY
from requests_mock import mock as requests_mock

from octodns.provider.yaml import YamlProvider
from octodns.record import Record
from octodns.zone import Zone

from octodns_vultr import (
    VultrClientNotFound,
    VultrClientUnauthorized,
    VultrProvider,
)

BASE = 'https://api.vultr.com/v2'


class TestVultrProvider(TestCase):
    expected = Zone('unit.tests.', [])
    source = YamlProvider(
        'test', join(dirname(__file__), 'config'), escaped_semicolons=False
    )
    source.populate(expected)

    # Our test suite differs a bit, add our NS and remove the simple one,
    # Vultr rejects records with IP-like NS targets in some setups
    expected.add_record(
        Record.new(
            expected,
            'under',
            {
                'ttl': 3600,
                'type': 'NS',
                'values': ['ns1.unit.tests.', 'ns2.unit.tests.'],
            },
        )
    )
    for record in list(expected.records):
        if record.name == 'sub' and record._type == 'NS':
            expected.remove_record(record)
            break

    def _mock_zone(self, mock):
        with open('tests/fixtures/vultr-domains-page-1.json') as fh:
            mock.get(f'{BASE}/domains', [{'text': fh.read()}])
        with open('tests/fixtures/vultr-records-page-1.json') as fh:
            p1 = fh.read()
        with open('tests/fixtures/vultr-records-page-2.json') as fh:
            p2 = fh.read()
        mock.get(
            f'{BASE}/domains/unit.tests/records', [{'text': p1}, {'text': p2}]
        )

    def test_populate(self):
        provider = VultrProvider('test', 'token')

        # Bad auth
        with requests_mock() as mock:
            mock.get(ANY, status_code=401, json={'error': 'Invalid API token'})

            with self.assertRaises(VultrClientUnauthorized):
                zone = Zone('unit.tests.', [])
                provider.populate(zone)

        # General error
        with requests_mock() as mock:
            mock.get(ANY, status_code=502, text='Things caught fire')

            with self.assertRaises(HTTPError) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(502, ctx.exception.response.status_code)

        # Non-existent domain doesn't populate anything
        with requests_mock() as mock:
            mock.get(
                f'{BASE}/domains/unit.tests/records',
                status_code=404,
                json={'error': 'Invalid domain.'},
            )

            zone = Zone('unit.tests.', [])
            exists = provider.populate(zone)
            self.assertEqual(set(), zone.records)
            self.assertFalse(exists)

        # Fresh provider/zone, populate for real and check what we got
        provider = VultrProvider('test', 'token', strict_supports=False)
        with requests_mock() as mock:
            self._mock_zone(mock)

            zone = Zone('unit.tests.', [])
            exists = provider.populate(zone)
            self.assertTrue(exists)
            self.assertEqual(14, len(zone.records))

            # No diffs == no changes, exercises the full read-side parsing
            # for every supported type (SRV/CAA/SSHFP packed data, TXT
            # quoting, trailing-dot inconsistencies) in one go
            plan = provider.plan(self.expected)
            self.assertIsNone(plan)

        # 2nd populate makes no network calls/all from cache
        again = Zone('unit.tests.', [])
        provider.populate(again)
        self.assertEqual(14, len(again.records))

    def test_list_zones(self):
        provider = VultrProvider('test', 'token')

        with requests_mock() as mock:
            with open('tests/fixtures/vultr-domains-page-1.json') as fh:
                p1 = fh.read()
            with open('tests/fixtures/vultr-domains-page-2.json') as fh:
                p2 = fh.read()
            mock.get(f'{BASE}/domains', [{'text': p1}, {'text': p2}])

            self.assertEqual(
                ['other.com.', 'unit.tests.'], provider.list_zones()
            )

    def test_process_desired_zone_ttl_clamping(self):
        provider = VultrProvider('test', 'token', strict_supports=False)

        zone = Zone('unit.tests.', [])
        zone.add_record(
            Record.new(
                zone, 'low', {'ttl': 10, 'type': 'A', 'value': '1.2.3.4'}
            )
        )
        zone.add_record(
            Record.new(
                zone, 'high', {'ttl': 99999999, 'type': 'A', 'value': '1.2.3.4'}
            )
        )

        processed = provider._process_desired_zone(zone)
        by_name = {r.name: r for r in processed.records}
        self.assertEqual(60, by_name['low'].ttl)
        self.assertEqual(172800, by_name['high'].ttl)

        # and with strict_supports (the default) it raises instead of
        # silently clamping
        strict = VultrProvider('test', 'token')
        zone = Zone('unit.tests.', [])
        zone.add_record(
            Record.new(
                zone, 'low', {'ttl': 10, 'type': 'A', 'value': '1.2.3.4'}
            )
        )
        with self.assertRaises(Exception):
            strict._process_desired_zone(zone)

    def test_populate_skips_unsupported_record_type(self):
        provider = VultrProvider('test', 'token')
        provider._zone_records = {
            'unit.tests.': [
                {
                    'id': '1',
                    'type': 'PTR',
                    'name': 'ptr',
                    'data': 'ignored',
                    'priority': -1,
                    'ttl': 300,
                }
            ]
        }

        zone = Zone('unit.tests.', [])
        exists = provider.populate(zone)
        self.assertTrue(exists)
        self.assertEqual(set(), zone.records)

    def test_apply(self):
        provider = VultrProvider('test', 'token', strict_supports=False)

        resp = Mock()
        resp.json = Mock()

        # no matching domain, create everything. Only the first two calls
        # (zone_records during populate, the domain check during apply)
        # need to look like anything, the rest are record_create POSTs
        # whose return value is unused
        provider._client._request = Mock(
            side_effect=chain(
                [VultrClientNotFound(), VultrClientNotFound()], repeat(None)
            )
        )
        plan = provider.plan(self.expected)

        self.assertFalse(plan.exists)
        n = len(plan.changes)
        self.assertEqual(14, n)
        self.assertEqual(n, provider.apply(plan))

        request = provider._client._request
        request.assert_any_call(
            'POST', '/domains', data={'domain': 'unit.tests'}
        )
        # a simple multi-value record
        request.assert_any_call(
            'POST',
            '/domains/unit.tests/records',
            data={'type': 'A', 'name': 'www', 'data': '2.2.3.6', 'ttl': 300},
        )
        # an SRV record, weight/port packed in to data, priority separate
        request.assert_any_call(
            'POST',
            '/domains/unit.tests/records',
            data={
                'type': 'SRV',
                'name': '_srv._tcp',
                'data': '20 30 foo-1.unit.tests.',
                'priority': 10,
                'ttl': 600,
            },
        )
        # a CAA record, fully packed in to data
        request.assert_any_call(
            'POST',
            '/domains/unit.tests/records',
            data={
                'type': 'CAA',
                'name': '',
                'data': '0 issue "ca.unit.tests"',
                'ttl': 3600,
            },
        )
        # an SSHFP record, also fully packed
        request.assert_any_call(
            'POST',
            '/domains/unit.tests/records',
            data={
                'type': 'SSHFP',
                'name': '',
                'data': '1 1 bf6b6825d2977c511a475bbefb88aad54a92ac73',
                'ttl': 3600,
            },
        )

        request.reset_mock()

        # delete one, update one
        provider._client.records = Mock(
            return_value=[
                {
                    'id': '101',
                    'type': 'A',
                    'name': 'www',
                    'data': '1.2.3.4',
                    'priority': -1,
                    'ttl': 300,
                },
                {
                    'id': '102',
                    'type': 'A',
                    'name': 'ttl',
                    'data': '3.2.3.4',
                    'priority': -1,
                    'ttl': 3600,
                },
            ]
        )

        request.side_effect = None
        request.return_value = resp
        resp.json.side_effect = [{'domain': {'domain': 'unit.tests'}}]

        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted, 'ttl', {'ttl': 300, 'type': 'A', 'value': '3.2.3.4'}
            )
        )

        plan = provider.plan(wanted)
        self.assertTrue(plan.exists)
        self.assertEqual(2, len(plan.changes))
        self.assertEqual(2, provider.apply(plan))

        request.assert_has_calls(
            [
                call('DELETE', '/domains/unit.tests/records/101'),
                call('DELETE', '/domains/unit.tests/records/102'),
                call(
                    'POST',
                    '/domains/unit.tests/records',
                    data={
                        'type': 'A',
                        'name': 'ttl',
                        'data': '3.2.3.4',
                        'ttl': 300,
                    },
                ),
            ],
            any_order=True,
        )
