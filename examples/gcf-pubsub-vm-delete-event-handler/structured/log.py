import logging
import os
from abc import ABCMeta, abstractmethod
from enum import Enum
from google.cloud.logging.resource import Resource


class Result(Enum):
    """The overall result of the DNS cleanup for user reporting

    An OK result indicates the cleanup completed normally.

    A NOT_PROCESSED results is likely a result of losing the race against the
    VM delete operation and is intended to signal to the user they may need to
    cleanup DNS records using another mechanism (e.g. manually).
    """
    OK = 0
    NOT_PROCESSED = 1


class Severity(Enum):
    """Stackdriver severity levels

    See https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
    """
    DEFAULT = 0
    DEBUG = 100
    INFO = 200
    NOTICE = 300
    WARNING = 400
    ERROR = 500
    CRITICAL = 600
    ALERT = 700
    EMERGENCY = 800


class Detail(Enum):
    """Detailed results of the cleanup

    A LOST_RACE result indicates user intervention is necessary.
    """
    NO_OP = 0
    NO_MATCHES = 1
    RR_DELETED = 2
    VM_NO_IP = 3
    IGNORED_EVENT = 4
    LOST_RACE = 5
    RR_MISMATCH = 6
    RR_NOT_A_RECORD = 7
    RR_NAME_MISMATCH = 8
    RR_IP_MISMATCH = 9


class StructuredLog(metaclass=ABCMeta):
    """Base class to report structured log events

    Sub classes are expected to override message(), RESULT (Result), and
    DETAIL (Detail).

    Attributes:
        SEVERITY: Stackdriver Log Severity, see
            https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
    """

    @property
    @abstractmethod
    def RESULT(self):
        """Result code of the DNS cleanup, e.g. OK or NOT_PROCESSED"""
        pass

    @property
    @abstractmethod
    def DETAIL(self):
        """Detail code of the DNS cleanup, e.g. NO_OP, RR_DELETED, LOST_RACE"""
        pass

    SEVERITY = Severity.NOTICE
    LEVEL = logging.INFO

    def __init__(self, vm_uri: str, event_id: str):
        self.vm_uri = vm_uri
        self.event_id = event_id
        self.function_project = os.getenv('GCP_PROJECT')
        self.function_region = os.getenv('FUNCTION_REGION')
        self.function_name = os.getenv('FUNCTION_NAME')
        stream = os.getenv('DNS_VM_GC_REPORTING_LOG_STREAM')
        # The log stream structured reports are sent to.
        # https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
        if stream:
            self.log_name = stream
        else:
            self.log_name = (
                'projects/{}/logs/{}'
            ).format(self.function_project, self.function_name)

    @abstractmethod
    def message(self):
        """Returns a human readable log message"""
        raise NotImplementedError

    def info(self):
        """Assembles dict intended for jsonPayload"""
        return {
            'message': self.message(),
            'vm_uri': self.vm_uri,
            'result': self.RESULT.name,
            'detail': self.DETAIL.name,
        }

    def log_entry(self):
        """Assembles dict intended for use as LogEntry

        This structure is passed as keyword arguments to the
        google.cloud.logging.log_struct() function.

        https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
        """
        resource_labels = {
            'function_name': self.function_name,
            'project_id': self.function_project,
            'region': self.function_region,
        }
        resource = Resource(labels=resource_labels, type='cloud_function')
        log_entry = {
            'log_name': self.log_name,
            'labels': {
                'event_id': self.event_id,
            },
            'severity': self.SEVERITY.name,
            'resource': resource,
        }
        return log_entry


class NoOp(StructuredLog):
    RESULT = Result.OK
    DETAIL = Detail.NO_OP

    def message(self):
        return f"{self.vm_uri} No action taken (NO_OP)"


class IgnoredEventSubtype(StructuredLog):
    """Log for when pub/sub event subtype is ignored e.g. GCE_OPERATION_DONE"""
    SEVERITY = Severity.DEBUG
    RESULT = Result.OK
    LEVEL = logging.DEBUG
    DETAIL = Detail.IGNORED_EVENT

    def message(self):
        return ("No action taken, event_type is not "
                f"GCE_API_CALL for {self.vm_uri}")


class NoMatches(StructuredLog):
    SEVERITY = Severity.DEBUG
    RESULT = Result.OK
    LEVEL = logging.DEBUG
    DETAIL = Detail.NO_MATCHES

    def message(self):
        return f"{self.vm_uri} matches no DNS records (NO_MATCHES)"


class LostRace(StructuredLog):
    SEVERITY = Severity.WARNING
    RESULT = Result.NOT_PROCESSED
    LEVEL = logging.WARNING
    DETAIL = Detail.LOST_RACE

    def message(self):
        return f"{self.vm_uri} does not exist, likely lost race (LOST_RACE)"


class VmNoIp(StructuredLog):
    SEVERITY = Severity.INFO
    RESULT = Result.OK
    LEVEL = logging.INFO
    DETAIL = Detail.VM_NO_IP

    def message(self):
        return f"{self.vm_uri} has no IP address (VM_NO_IP)"


class RecordSkipped(StructuredLog):
    SEVERITY = Severity.DEBUG
    RESULT = Result.OK
    LEVEL = logging.DEBUG
    DETAIL = Detail.RR_MISMATCH

    def __init__(self, vm_uri: str, event_id: str, record: dict):
        super().__init__(vm_uri, event_id)
        self.record = record

    def message(self):
        return (f"{self.vm_uri} does not match DNS record "
                f"{self.record['name']} ({self.DETAIL.name})")


class NotARecord(RecordSkipped):
    DETAIL = Detail.RR_NOT_A_RECORD


class NameMismatch(RecordSkipped):
    DETAIL = Detail.RR_NAME_MISMATCH


class IpMismatch(RecordSkipped):
    DETAIL = Detail.RR_IP_MISMATCH


class RecordDeleted(StructuredLog):
    SEVERITY = Severity.NOTICE
    RESULT = Result.OK
    LEVEL = logging.INFO
    DETAIL = Detail.RR_DELETED

    def __init__(self, vm_uri: str, event_id: str, dns_project: str,
                 dns_managed_zone: str, record: dict, response: dict):
        """The structure of record is a dns#resourceRecordSet

        See: https://cloud.google.com/dns/docs/reference/v1/resourceRecordSets
        """
        super().__init__(vm_uri, event_id)
        self.dns_project = dns_project
        self.dns_managed_zone = dns_managed_zone
        self.record = record
        self.response = response

    def message(self):
        return (f"{self.vm_uri} matches DNS record {self.record['name']} "
                f"deleted ({self.DETAIL.name})")

    def info(self):
        info = super().info()
        info.update({
            'dns_project': self.dns_project,
            'dns_managed_zone': self.dns_managed_zone,
            'dns_record': self.record,
            'response': self.response,
        })
        return info
