#
#
#

import logging
from collections import defaultdict

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.1'


class VultrClientException(ProviderException):
    pass


class VultrClientNotFound(VultrClientException):
    def __init__(self):
        super().__init__('Not Found')


class VultrClientUnauthorized(VultrClientException):
    def __init__(self):
        super().__init__('Unauthorized')


class VultrClient(object):
    BASE = 'https://api.vultr.com/v2'

    def __init__(self, token):
        sess = Session()
        sess.headers.update(
            {
                'Authorization': f'Bearer {token}',
                'User-Agent': f'octodns/{octodns_version} octodns-vultr/{__VERSION__}',
            }
        )
        self._sess = sess

    def _request(self, method, path, params=None, data=None):
        url = f'{self.BASE}{path}'
        resp = self._sess.request(method, url, params=params, json=data)
        if resp.status_code == 401:
            raise VultrClientUnauthorized()
        if resp.status_code == 404:
            raise VultrClientNotFound()
        resp.raise_for_status()
        return resp

    def _paginated(self, path, key):
        ret = []

        cursor = None
        while True:
            params = {'cursor': cursor} if cursor else None
            data = self._request('GET', path, params).json()

            ret += data[key]

            cursor = data['meta']['links']['next']
            if not cursor:
                break

        return ret

    def domains(self):
        return self._paginated('/domains', 'domains')

    def domain(self, name):
        return self._request('GET', f'/domains/{name}').json()['domain']

    def domain_create(self, name):
        self._request('POST', '/domains', data={'domain': name})

    def records(self, domain):
        return self._paginated(f'/domains/{domain}/records', 'records')

    def record_create(self, domain, params):
        self._request('POST', f'/domains/{domain}/records', data=params)

    def record_delete(self, domain, record_id):
        self._request('DELETE', f'/domains/{domain}/records/{record_id}')


class VultrProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(
        ('A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'SRV', 'SSHFP', 'TXT')
    )

    # Vultr clamps any ttl outside of this range rather than rejecting it,
    # https://www.vultr.com/api/#tag/dns
    MIN_TTL = 60
    MAX_TTL = 172800

    def __init__(self, id, token, *args, **kwargs):
        self.log = logging.getLogger(f'VultrProvider[{id}]')
        self.log.debug('__init__: id=%s, token=***', id)
        super().__init__(id, *args, **kwargs)
        self._client = VultrClient(token)

        self._zone_records = {}

    def _normalize_ttl(self, ttl):
        return max(self.MIN_TTL, min(self.MAX_TTL, ttl))

    def _process_desired_zone(self, desired):
        for record in desired.records:
            ttl = record.ttl
            normalized = self._normalize_ttl(ttl)
            if normalized != ttl:
                msg = f'ttl {ttl} is not supported by Vultr, {record.fqdn}'
                fallback = f'clamping to {normalized}'
                self.supports_warn_or_except(msg, fallback)
                record = record.copy()
                record.ttl = normalized
                desired.add_record(record, replace=True)

        return super()._process_desired_zone(desired)

    @staticmethod
    def _fqdn(value):
        # Vultr is inconsistent about whether a target comes back with its
        # trailing dot already attached (SRV does, NS/CNAME/MX don't), so
        # only add one if it's missing rather than assuming either way
        return value if value.endswith('.') else f'{value}.'

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                self._zone_records[zone.name] = self._client.records(
                    zone.name[:-1]
                )
            except VultrClientNotFound:
                return []

        return self._zone_records[zone.name]

    def list_zones(self):
        self.log.debug('list_zones:')
        return sorted(f'{d["domain"]}.' for d in self._client.domains())

    def _data_for_multiple(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [r['data'] for r in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_NS(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [self._fqdn(r['data']) for r in records],
        }

    def _data_for_CNAME(self, _type, records):
        record = records[0]
        return {
            'ttl': record['ttl'],
            'type': _type,
            'value': self._fqdn(record['data']),
        }

    def _data_for_MX(self, _type, records):
        values = [
            {'preference': r['priority'], 'exchange': self._fqdn(r['data'])}
            for r in records
        ]
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_SRV(self, _type, records):
        values = []
        for r in records:
            weight, port, target = r['data'].split(' ', 2)
            values.append(
                {
                    'priority': r['priority'],
                    'weight': int(weight),
                    'port': int(port),
                    'target': self._fqdn(target),
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_CAA(self, _type, records):
        values = []
        for r in records:
            flags, tag, value = r['data'].split(' ', 2)
            values.append(
                {'flags': int(flags), 'tag': tag, 'value': value.strip('"')}
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_SSHFP(self, _type, records):
        values = []
        for r in records:
            algorithm, fingerprint_type, fingerprint = r['data'].split(' ', 2)
            values.append(
                {
                    'algorithm': int(algorithm),
                    'fingerprint_type': int(fingerprint_type),
                    'fingerprint': fingerprint,
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_TXT(self, _type, records):
        values = [r['data'].strip('"').replace(';', '\\;') for r in records]
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            _type = record['type']
            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue
            values[record['name']][record['type']].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, type_records in types.items():
                data_for = getattr(self, f'_data_for_{_type}')
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, type_records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _params_for_multiple(self, record):
        for value in record.values:
            yield {
                'type': record._type,
                'name': record.name,
                'data': value,
                'ttl': record.ttl,
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple
    _params_for_NS = _params_for_multiple

    def _params_for_single(self, record):
        yield {
            'type': record._type,
            'name': record.name,
            'data': record.value,
            'ttl': record.ttl,
        }

    _params_for_CNAME = _params_for_single

    def _params_for_MX(self, record):
        for value in record.values:
            yield {
                'type': record._type,
                'name': record.name,
                'data': value.exchange,
                'priority': value.preference,
                'ttl': record.ttl,
            }

    def _params_for_SRV(self, record):
        for value in record.values:
            yield {
                'type': record._type,
                'name': record.name,
                'data': f'{value.weight} {value.port} {value.target}',
                'priority': value.priority,
                'ttl': record.ttl,
            }

    def _params_for_CAA(self, record):
        for value in record.values:
            yield {
                'type': record._type,
                'name': record.name,
                'data': f'{value.flags} {value.tag} "{value.value}"',
                'ttl': record.ttl,
            }

    def _params_for_SSHFP(self, record):
        for value in record.values:
            yield {
                'type': record._type,
                'name': record.name,
                'data': f'{value.algorithm} {value.fingerprint_type} {value.fingerprint}',
                'ttl': record.ttl,
            }

    def _params_for_TXT(self, record):
        # Vultr wraps values in quotes itself and doesn't want octoDNS's
        # escaped semicolons, so strip them here and add them back when
        # going the other way
        for value in record.values:
            yield {
                'type': record._type,
                'name': record.name,
                'data': value.replace('\\;', ';'),
                'ttl': record.ttl,
            }

    def _apply_Create(self, change):
        new = change.new
        params_for = getattr(self, f'_params_for_{new._type}')
        for params in params_for(new):
            self._client.record_create(new.zone.name[:-1], params)

    def _apply_Update(self, change):
        self._apply_Delete(change)
        self._apply_Create(change)

    def _apply_Delete(self, change):
        existing = change.existing
        zone = existing.zone
        for record in self.zone_records(zone):
            if (
                existing.name == record['name']
                and existing._type == record['type']
            ):
                self._client.record_delete(zone.name[:-1], record['id'])

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        domain_name = desired.name[:-1]
        try:
            self._client.domain(domain_name)
        except VultrClientNotFound:
            self.log.debug('_apply:   no matching domain, creating')
            self._client.domain_create(domain_name)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        # Clear out the cache, it's no longer valid after changes
        self._zone_records.pop(desired.name, None)
