# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

__author__ = ('Jeff McCune <jeff@openinfrastructure.co>, '
              'Gary Larizza <gary@openinfrastructure.co>')

import base64
import json
import logging
import os
import google.cloud.logging
from structured import log
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from typing import List


class RuntimeState:
    """Stores App instance for the lifetime of the process"""
    pass


RuntimeState.app = None


class EventHandler():
    """Handles a single event.

    Intended to follow the lifecycle of a single trigger event.
    """

    def __init__(self, app, data, context=None):
        self.config = self.load_configuration()
        self.log = app.log
        self.cloud_log = app.cloud_log
        self.compute = app.compute
        self.dns = app.dns
        self.event_id = context.event_id if context else context
        event = self.parse_data(data)
        self.type = event['type']
        self.event_subtype = event['event_subtype']
        self.resource_type = event['resource_type']
        self.project = event['project']
        self.zone = event['zone']
        self.vm_name = event['vm_name']
        self.vm_uri = (f"projects/{self.project}/zones/{self.zone}"
                       f"/instances/{self.vm_name}")
        # https://cloud.google.com/functions/docs/env-var
        self.function_project = os.getenv('GCP_PROJECT')
        self.function_region = os.getenv('FUNCTION_REGION')
        self.function_name = os.getenv('FUNCTION_NAME')
        self.debug = True if os.getenv('DEBUG') else False

    def load_configuration(self):
        """Loads configuration from the environment

        Returns:
          Dictionary of config key/values.
        """
        dns_zones = os.getenv('DNS_VM_GC_MANAGED_ZONES')
        if not dns_zones:
            raise(EnvironmentError(
                'Env var DNS_VM_GC_MANAGED_ZONES is required'))
        zones = [v.strip() for v in dns_zones.split(',')]
        return {'dns_zones': zones}

    def log_event(self, event: log.StructuredLog):
        """Logs a structured event intended for end user reporting"""
        if event.SEVERITY == log.Severity.DEBUG and not self.debug:
            return
        self.log.log(event.LEVEL, event.message())
        self.cloud_log.log_struct(info=event.info(), **event.log_entry())

    def run(self):
        """Processes an event"""
        valid_event = self.validate_event_type(
            event_type=self.type,
            event_subtype=self.event_subtype,
            resource_type=self.resource_type,
        )
        if not valid_event:
            self.log_event(log.IgnoredEventSubtype(self.vm_uri, self.event_id))
            return 0

        msg = "Handling event_id='{}' vm='{}'".format(
            self.event_id,
            self.vm_uri
        )
        self.log.info(msg)

        instance = self.get_instance(self.project, self.zone, self.vm_name)
        if not instance:
            self.log_event(log.LostRace(self.vm_uri, self.event_id))
            return 0

        ip = self.ip_address(instance)
        if not ip:
            self.log_event(log.VmNoIp(self.vm_uri, self.event_id))
            return 0

        num_deleted = 0
        for zone in self.config['dns_zones']:
            records = self.get_dns_records(zone)
            candidates = self.find_garbage_dns_entries(
                self.vm_name, ip, records)
            for record in candidates:
                self.delete_record(zone, record)
                num_deleted += 1
        return num_deleted

    def get_dns_records(self, zone: str) -> List[dict]:
        """Obtain a collection of A records from Cloud DNS.

        See
        https://cloud.google.com/dns/docs/reference/v1/resourceRecordSets/list

        Args:
            zone: The Cloud DNS managed zone to scan for records.  Must be
            specified as a fully qualified URI, e.g.
            projects/my-vpc-host/managedZones/my-dns-zone
        """
        (_, project, _, managed_zone) = zone.split('/')
        request = self.dns.resourceRecordSets().list(
            project=project,
            managedZone=managed_zone
        )
        records = []
        while request is not None:
            try:
                response = request.execute()
                for resource_record_set in response['rrsets']:
                    records.append(resource_record_set)
                request = self.dns.resourceRecordSets().list_next(
                    previous_request=request,
                    previous_response=response)
            except HttpError as err:
                msg = (
                    'Could not get DNS records.  Check the managed '
                    'zones specified in DNS_VM_GC_MANAGED_ZONES exist.'
                    'Detail: {}'
                ).format(err)
                self.log.error(msg)
                request = None
        return records

    def delete_record(self, zone: str, record: dict):
        """Deletes a DNS Resource Record Set.

        See https://cloud.google.com/dns/docs/reference/v1/changes

        Args:
            zone: The Cloud DNS managed zone to scan for records.  Must be
                specified as a fully qualified URI, e.g.
                projects/my-host-vpc/managedZones/my-dns-zone
            record: A DNS record dictionary, must have at least 'name' key and
                value.
        """
        (_, project, _, managed_zone) = zone.split('/')
        change = {"kind": "dns#change", "deletions": [record]}
        request = self.dns.changes().create(
            project=project,
            managedZone=managed_zone,
            body=change)
        response = request.execute()

        event = log.RecordDeleted(self.vm_uri, self.event_id, project,
                                  managed_zone, record, response,)
        self.log_event(event)
        return response

    def find_garbage_dns_entries(
            self,
            instance: str,
            ip: str,
            records: List[dict]) -> List[dict]:
        """Identifies DNS records to delete.

        Records are included in the results to be deleted if:
        1. The leftmost portion of the DNS Record name matches the vm name.
        2. AND the rrdatas value has exactly one value matching the ip.
        3. AND the DNS record type is 'A'

        Args:
            instance: The name of the instance.
            ip: The IP address of the VM being deleted.
            records: A list of DNS records as returned from the dns v1 API.
        """
        candidates = []

        for record in records:
            if 'A' != record['type']:
                self.log_event(log.NotARecord(self.vm_uri, self.event_id,
                                              record))
                continue
            if instance != record['name'].split('.')[0]:
                self.log_event(log.NameMismatch(self.vm_uri, self.event_id,
                                                record))
                continue
            if [ip] != record['rrdatas']:
                self.log_event(log.IpMismatch(self.vm_uri, self.event_id,
                                              record))
                continue
            candidates.append(record)
        return candidates

    def ip_address(self, instance):
        """Parses the primary network IP from a VM instance Resource.

        Args:
        Returns: (string) ip address or None if IP not found
        """
        ip = None
        try:
            return instance.get('networkInterfaces')[0].get('networkIP')
        except (AttributeError, IndexError, KeyError, TypeError):
            return None
        return ip

    def get_instance(self, project, compute_zone, instance):
        """Return the results of the compute.instances.get API call
        Args:
            project (string): The project
            compute_zone (string): The compute_zone
            instance (string): The instance name
        Returns:
            (dict) De-serialized JSON API response as a Dictionary.
        """
        try:
            result = self.compute.instances().get(
                project=project,
                zone=compute_zone,
                instance=instance).execute()
        except HttpError as err:
            self.log.error("Getting {}: {}".format(self.vm_uri, err))
            result = {}
        return result

    def parse_data(self, data):
        """Parses event data

        Args:
          data (dict): The value of the data key of the trigger event.

        Returns a dictionary with the following keys:
          project: The project the VM resided in.
          zone: The compute zone the VM resided in.
          instance: The name of the VM instance.
          type: The event type, e.g. GCE_API_CALL
          event_subtype: The event subtype, e.g. compute.instances.delete
          resource_type: The resource type, e.g. gce_instance
        """
        # Event metadata comes from Stackdriver as a JSON string
        event_json = base64.b64decode(data['data']).decode('utf-8')
        event = json.loads(event_json)

        struct = {
            'project': event['resource']['labels']['project_id'],
            'zone': event['resource']['labels']['zone'],
            'vm_name': event['labels'][
                'compute.googleapis.com/resource_name'
            ],
            'type': event['jsonPayload']['event_type'],
            'event_subtype': event['jsonPayload']['event_subtype'],
            'resource_type': event['resource']['type'],
        }

        return struct

    def validate_event_type(self, event_type: str, event_subtype: str,
                            resource_type: str):
        """Validates the event type is one which should be handled.

        Events must match the following filter to trigger the cleanup process:

                resource.type="gce_instance"
                jsonPayload.event_type="GCE_API_CALL"
                jsonPayload.event_subtype="compute.instances.delete"

        Returns (bool): True if the event should be handled.
        """
        if event_type == 'GCE_API_CALL' \
                and event_subtype == 'compute.instances.delete' \
                and resource_type == 'gce_instance':
            return True
        return False


class DnsVmGcApp():
    """Holds state for the lifetime of a function

    Application controller holding state which persists across multiple trigger
    events.  Primarily configuration, network API clients, and logging API
    clients.
    """
    LOGNAME = 'dns-vm-gc'

    def __init__(self, http=None, session=None):
        """Initializes the app to handle multiple events

        Args:
            http: httplib2.Http, An instance of httplib2.Http or something that
                acts like it that HTTP requests will be made through.
            session: A requests.Session instance intended for mocking out the
                Stackdriver API when under test.
        """
        # Log clients
        self.log = self.setup_python_logging()
        self.cloud_log = self.setup_cloud_logging(session=session)
        # API clients
        self.compute = discovery.build('compute', 'v1', http=http)
        self.dns = discovery.build('dns', 'v1', http=http)

    def setup_python_logging(self):
        """Configures Python logging system

        Python logs are sent to STDOUT and STDERR by default.  In GCF, these
        logs are associated on execution_id.
        """
        if os.getenv('DEBUG'):
            level = logging.DEBUG
        else:
            level = logging.INFO
        # Make googleapiclient less noisy.
        # See https://github.com/googleapis/google-api-python-client/issues/299
        api_logger = logging.getLogger('googleapiclient')
        api_logger.setLevel(logging.ERROR)
        # Set level of our logger.
        log = logging.getLogger(self.LOGNAME)
        log.setLevel(level)
        return log

    def setup_cloud_logging(self, session=None):
        """Configures Structured Logging for results reporting

        Structured logs are used to report the results of execution.  This is
        different from Python logging used to report step by step progress of a
        single execution.

        Args:
            session: A requests.Session instance intended for mocking out the
                Stackdriver API when under test.
        """
        if session:
            client = google.cloud.logging.Client(
                _http=session,
                _use_grpc=False
            )
        else:
            client = google.cloud.logging.Client()
        logger = client.logger(self.LOGNAME)
        return logger

    def handle_event(self, data, context=None):
        """Background Cloud Function to delete DNS A records when VM is deleted.

        Args:
            data (dict): The dictionary with data specific to this type of
                event.
            context (google.cloud.functions.Context): The Cloud Functions event
                metadata.
        Returns:
            Number of records deleted across all managed zones.
        """
        handler = EventHandler(app=self, data=data, context=context)
        result = handler.run()
        return result


def dns_vm_gc(data, context=None, http=None, session=None):
    if RuntimeState.app is None:
        RuntimeState.app = DnsVmGcApp(http=http, session=session)
    result = RuntimeState.app.handle_event(data, context)
    return result
