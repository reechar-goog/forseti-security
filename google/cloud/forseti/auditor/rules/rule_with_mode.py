from rule import Rule
from abc import ABCMeta, abstractmethod
from enum import Enum
from google.cloud.forseti.common.util import log_util
from rule_errors import InvalidModeError


LOGGER = log_util.get_logger(__name__)


class RuleMode(Enum):
    """Enum for rule modes"""
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    REQUIRED = "required"


class RuleWithMode(Rule):
    """
    The abstract base class for rules with mode
    e.g. IAM rule, Groups rule, Forwarding rule
    """
    __metaclass__ = ABCMeta

    def __init__(self, mode, **kwargs):
        """Initialize

        Args:
            mode (string): the mode of the rule
            **kwargs (dict): the rest of the params
                for the base class
        """
        self.mode = mode
        super(**kwargs)

    def audit(self, resource):
        """
        Audit the resource

        Args:
            resource (dict): resource to be audited

        Raise:
            KeyError
        """
        try:
            self.audit_mapping[self.mode.lower()]()
        except KeyError:
            raise InvalidModeError("Input mode is invalid")

    @abstractmethod
    def audit_whitelist(self, resource):
        """
        audit in whitelist mode

        Args:
            resource (dict): resource to be audited
        """
        pass

    @abstractmethod
    def audit_blacklist(self, resource):
        """audit in blacklist mode

            Args:
                resource (dict): resource to be audited
        """
        pass

    @abstractmethod
    def audit_required(self, resource):
        """audit in required mode

            Args:
                resource (dict): resource to be audited
        """
        pass

    audit_mapping = {
        RuleMode.WHITELIST: audit_whitelist,
        RuleMode.BLACKLIST: audit_blacklist,
        RuleMode.REQUIRED: audit_required
    }
