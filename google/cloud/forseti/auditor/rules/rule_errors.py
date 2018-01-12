class Error(Exception):
    """Base Error class."""


class AuditError(Error):
    """AuditError."""


class InvalidModeError(AuditError):
    """InvalidModeError"""


class InvalidRuleTypeError(AuditError):
    """InvalidRuleTypeError."""

    def __init__(self, rule_type):
        """Init.

        Args:
            rule_type (str): The rule type.
        """
        super(InvalidRuleTypeError, self).__init__(
            'Invalid rule type: {}'.format(rule_type))


class ResourceDataError(AuditError):
    """ResourceDataError."""

    def __init__(self, resource_data):
        """Init.

        Args:
            resource_data (str): The resource data.
        """
        super(ResourceDataError, self).__init__(
            'Resource data could not be audited: {}'.format(resource_data))
