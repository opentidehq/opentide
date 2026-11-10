"""The GravityZone criteria catalogue for the EDR targets (bitdefender-1.0, Criteria catalogue).

Generated from opentidehq/language-server ``catalogs/bitdefender/criteria.toml``
(#228), itself generated from Bitdefender's "Detection and exclusion criteria
for Basic rules": facts only (field names, the sensors that evaluate each field
and value, relations, value kinds, values, ranges and the pairing rules),
rewritten as data. The detection fields of ``process``, ``file``,
``connection`` and ``registry`` equal that catalogue's; regenerate both
together. Fields of other targets are not listed: an unknown field there is a
warning in the spec, not an error.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Field:
    """One detection field of an EDR target."""

    target: str
    #: The sensor that evaluates it: ``edr``, ``xdr`` or ``both``.
    availability: str
    relations: tuple[str, ...]
    #: ``string``, ``hash``, ``ip``, ``port`` or ``enum``.
    kind: str
    #: Enum values and the sensor that evaluates each.
    values: dict[str, str] = field(default_factory=dict)
    #: Fields a rule using that enum value may not also have.
    value_incompatible: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: One of these must also be a criterion of the rule.
    requires_any: tuple[str, ...] = ()
    #: The same, in a detection rule, where ``detection`` is the block's ``alert``.
    detection_requires_any: tuple[str, ...] = ()
    #: Fields that may not be criteria of the same rule.
    incompatible: tuple[str, ...] = ()
    #: The XDR resource the field is about (one per connection rule).
    resource: str | None = None
    minimum: int | None = None
    maximum: int | None = None


#: Full registry hive names and the short names GravityZone matches.
REGISTRY_HIVES: dict[str, str] = {
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_CURRENT_USER": "HKCU",
    "HKEY_USERS": "HKU",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKEY_CURRENT_CONFIG": "HKCC",
}

#: Targets with one XDR resource per rule (``one_resource``).
ONE_RESOURCE_TARGETS: frozenset[str] = frozenset(["connection", "user connection"])

#: ``alert_or_operation`` rules: ``(target or None, field or None, scope, require)``.
ALERT_OR_OPERATION: tuple[tuple[str | None, str | None, str, bool], ...] = (
    (None, None, "xdr", False),
    ("file", "File.Operation", "xdr", True),
    ("email", "Email.Operation", "all", True),
    ("application", "Application.Operation", "all", True),
    ("key vault", "KeyVault.Operation", "all", True),
    ("role", "Role.Operation", "all", True),
    ("policy", "Policy.Operation", "all", True),
    ("sharing link", "SharingLink.Operation", "all", True),
    ("url", "Url.Operation", "all", True),
    ("ssh key", "SshKey.Operation", "all", True),
    ("launch template", "LaunchTemplate.Operation", "all", True),
    ("service principal", "ServicePrincipal.Operation", "all", True),
    ("user group", "UserGroup.Operation", "all", True),
    ("automation account", "AutomationAccount.Operation", "all", True),
    ("automation account hook", "AutomationAccountHook.Operation", "all", True),
    ("api", "Api.Operation", "all", True),
    ("certificate authority", "CertificateAuthority.Operation", "all", True),
    ("bucket", "Bucket.Operation", "all", True),
    ("jira project", "JiraProject.Operation", "all", True),
    ("confluence page", "ConfluencePage.Operation", "all", True),
)

FIELDS: dict[str, Field] = {
    "Process.Name": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.Path": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.FullPathName": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.CommandLine": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.Parent.Name": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.Parent.Path": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.Parent.FullPathName": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.Parent.CommandLine": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.User": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Process.MD5": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="hash"
    ),
    "Process.SHA2": Field(
        target="process", availability="edr", relations=("is", "contains", "any"), kind="hash"
    ),
    "File.Name": Field(
        target="file", availability="both", relations=("is", "contains", "any"), kind="string"
    ),
    "File.Path": Field(
        target="file", availability="both", relations=("is", "contains", "any"), kind="string"
    ),
    "File.FullPathName": Field(
        target="file", availability="both", relations=("is", "contains", "any"), kind="string"
    ),
    "File.Operation": Field(
        target="file",
        availability="both",
        relations=("is", "any"),
        kind="enum",
        values={
            "rename": "edr",
            "copy": "edr",
            "create": "edr",
            "shared": "xdr",
            "downloaded": "xdr",
            "uploaded": "xdr",
            "read": "both",
            "write": "both",
            "move": "both",
        },
    ),
    "File.CreatedBy.Name": Field(
        target="file", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "File.CreatedBy.Path": Field(
        target="file", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "File.CreatedBy.FullPathName": Field(
        target="file", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "File.CreatedBy.CommandLine": Field(
        target="file", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "File.CreatedBy.User": Field(
        target="file", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "File.CertificateSigner": Field(
        target="file",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        requires_any=("File.Name", "File.FullPathName"),
    ),
    "File.CertificateIssuer": Field(
        target="file",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        requires_any=("File.Name", "File.FullPathName"),
    ),
    "File.CertificateSignedStatus": Field(
        target="file",
        availability="edr",
        relations=("is",),
        kind="enum",
        values={"is_signed": "edr", "is_unsigned": "edr"},
        value_incompatible={"is_unsigned": ("File.CertificateIssuer", "File.CertificateSigner")},
        requires_any=("File.Name", "File.FullPathName"),
    ),
    "File.MD5": Field(
        target="file", availability="xdr", relations=("is", "contains", "any"), kind="hash"
    ),
    "File.SHA2": Field(
        target="file", availability="xdr", relations=("is", "contains", "any"), kind="hash"
    ),
    "File.Url": Field(
        target="file", availability="xdr", relations=("is", "contains", "any"), kind="string"
    ),
    "File.SourceIP": Field(
        target="file", availability="xdr", relations=("is", "contains", "any"), kind="ip"
    ),
    "File.DestinationIP": Field(
        target="file", availability="xdr", relations=("is", "contains", "any"), kind="ip"
    ),
    "Connection.SourceIP": Field(
        target="connection", availability="both", relations=("is", "contains", "any"), kind="ip"
    ),
    "Connection.DestinationIP": Field(
        target="connection", availability="both", relations=("is", "contains", "any"), kind="ip"
    ),
    "Connection.SourcePort": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="port",
        minimum=0,
        maximum=65535,
    ),
    "Connection.DestinationPort": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="port",
        minimum=0,
        maximum=65535,
    ),
    "Connection.Process.Name": Field(
        target="connection", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Connection.Process.Path": Field(
        target="connection", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Connection.Process.FullPathName": Field(
        target="connection", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Connection.Process.CommandLine": Field(
        target="connection", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Connection.Process.User": Field(
        target="connection", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Connection.URL": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.TelnetUser",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
            "Connection.SSHUser",
            "Connection.WMIExecQuery",
        ),
    ),
    "Connection.HTTPUser": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
        ),
    ),
    "Connection.HTTPDownloadedFile": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
        ),
    ),
    "Connection.HTTPUploadedFile": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
        ),
    ),
    "Connection.FTPUser": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.Domain",
            "Connection.HTTPUser",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.URL",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
        ),
    ),
    "Connection.SMBDomain": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.HTTPUser",
            "Connection.URL",
        ),
    ),
    "Connection.SMBSharePath": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.HTTPUser",
            "Connection.URL",
        ),
    ),
    "Connection.SMBUser": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.HTTPUser",
            "Connection.URL",
        ),
    ),
    "Connection.SSHUser": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.Domain",
            "Connection.HTTPUser",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.URL",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
        ),
    ),
    "Connection.WMIExecQuery": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.Domain",
            "Connection.HTTPUser",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.TelnetUser",
            "Connection.URL",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
            "Connection.SSHUser",
        ),
    ),
    "Connection.TelnetUser": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.Domain",
            "Connection.HTTPUser",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.URL",
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
            "Connection.SSHUser",
            "Connection.WMIExecQuery",
        ),
    ),
    "Connection.FileRemotePath": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        incompatible=(
            "Connection.Domain",
            "Connection.FTPUser",
            "Connection.HTTPUser",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.URL",
        ),
    ),
    "Connection.Domain": Field(
        target="connection",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        requires_any=("Connection.Protocol",),
        incompatible=(
            "Connection.FileRemotePath",
            "Connection.FileRemoteOperation",
            "Connection.FTPUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
        ),
    ),
    "Connection.FileRemoteOperation": Field(
        target="connection",
        availability="edr",
        relations=("is", "any"),
        kind="enum",
        values={"create": "edr", "rem_delete": "edr", "read": "edr", "write": "edr", "move": "edr"},
        incompatible=(
            "Connection.Domain",
            "Connection.FTPUser",
            "Connection.HTTPUser",
            "Connection.HTTPDownloadedFile",
            "Connection.HTTPUploadedFile",
            "Connection.SMBDomain",
            "Connection.SMBSharePath",
            "Connection.SMBUser",
            "Connection.SSHUser",
            "Connection.TelnetUser",
            "Connection.WMIExecQuery",
            "Connection.URL",
        ),
    ),
    "Connection.Protocol": Field(
        target="connection",
        availability="edr",
        relations=("is",),
        kind="enum",
        values={"http/https": "edr", "smb": "edr"},
        value_incompatible={
            "http/https": ("Connection.SMBDomain", "Connection.SMBSharePath", "Connection.SMBUser"),
            "smb": (
                "Connection.URL",
                "Connection.HTTPUser",
                "Connection.HTTPDownloadedFile",
                "Connection.HTTPUploadedFile",
            ),
        },
        requires_any=("Connection.Domain",),
    ),
    "Connection.File.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.File.Operation", "detection"),
        resource="File",
    ),
    "Connection.Email.Subject": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.Email.Operation", "detection"),
        resource="Email",
    ),
    "Connection.Application.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.Application.Operation", "detection"),
        resource="Application",
    ),
    "Connection.KeyVault.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.KeyVault.Operation", "detection"),
        resource="KeyVault",
    ),
    "Connection.Role.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.Role.Operation", "detection"),
        resource="Role",
    ),
    "Connection.Policy.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.Policy.Operation", "detection"),
        resource="Policy",
    ),
    "Connection.SharingLink.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.SharingLink.Operation", "detection"),
        resource="SharingLink",
    ),
    "Connection.Url.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.Url.Operation", "detection"),
        resource="Url",
    ),
    "Connection.SshKey.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.SshKey.Operation", "detection"),
        resource="SshKey",
    ),
    "Connection.LaunchTemplate.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.LaunchTemplate.Operation", "detection"),
        resource="LaunchTemplate",
    ),
    "Connection.ServicePrincipal.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.ServicePrincipal.Operation", "detection"),
        resource="ServicePrincipal",
    ),
    "Connection.UserGroup.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.UserGroup.Operation", "detection"),
        resource="UserGroup",
    ),
    "Connection.AutomationAccount.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.AutomationAccount.Operation", "detection"),
        resource="AutomationAccount",
    ),
    "Connection.AutomationAccountHook.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.AutomationAccountHook.Operation", "detection"),
        resource="AutomationAccountHook",
    ),
    "Connection.Api.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.Api.Operation", "detection"),
        resource="Api",
    ),
    "Connection.CertificateAuthority.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.CertificateAuthority.Operation", "detection"),
        resource="CertificateAuthority",
    ),
    "Connection.Bucket.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.Bucket.Operation", "detection"),
        resource="Bucket",
    ),
    "Connection.SourceUser": Field(
        target="connection", availability="xdr", relations=("is", "contains", "any"), kind="string"
    ),
    "Connection.DestinationUser": Field(
        target="connection", availability="xdr", relations=("is", "contains", "any"), kind="string"
    ),
    "Connection.ConfluencePage.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.ConfluencePage.Operation", "detection"),
        resource="ConfluencePage",
    ),
    "Connection.JiraProject.Name": Field(
        target="connection",
        availability="xdr",
        relations=("is", "contains", "any"),
        kind="string",
        detection_requires_any=("Connection.JiraProject.Operation", "detection"),
        resource="JiraProject",
    ),
    "Connection.Api.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"modified": "xdr", "deleted": "xdr"},
        requires_any=("Connection.Api.Name",),
        resource="Api",
    ),
    "Connection.Application.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={
            "created": "xdr",
            "deleted": "xdr",
            "authorized": "xdr",
            "permission_changed": "xdr",
        },
        requires_any=("Connection.Application.Name",),
        resource="Application",
    ),
    "Connection.AutomationAccountHook.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"created": "xdr"},
        requires_any=("Connection.AutomationAccountHook.Name",),
        resource="AutomationAccountHook",
    ),
    "Connection.AutomationAccount.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"created": "xdr"},
        requires_any=("Connection.AutomationAccount.Name",),
        resource="AutomationAccount",
    ),
    "Connection.Bucket.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"created": "xdr", "deleted": "xdr", "upload": "xdr", "download": "xdr"},
        requires_any=("Connection.Bucket.Name",),
        resource="Bucket",
    ),
    "Connection.CertificateAuthority.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"created": "xdr", "assigned": "xdr"},
        requires_any=("Connection.CertificateAuthority.Name",),
        resource="CertificateAuthority",
    ),
    "Connection.ConfluencePage.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"public_link_created": "xdr"},
        requires_any=("Connection.ConfluencePage.Name",),
        resource="ConfluencePage",
    ),
    "Connection.Email.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"sent": "xdr", "received": "xdr"},
        requires_any=("Connection.Email.Subject",),
        resource="Email",
    ),
    "Connection.File.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"shared": "xdr", "downloaded": "xdr", "uploaded": "xdr"},
        requires_any=("Connection.File.Name",),
        resource="File",
    ),
    "Connection.JiraProject.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"deleted": "xdr", "modified": "xdr"},
        requires_any=("Connection.JiraProject.Name",),
        resource="JiraProject",
    ),
    "Connection.KeyVault.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"created": "xdr", "deleted": "xdr", "authorized": "xdr"},
        requires_any=("Connection.KeyVault.Name",),
        resource="KeyVault",
    ),
    "Connection.LaunchTemplate.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"create": "xdr"},
        requires_any=("Connection.LaunchTemplate.Name",),
        resource="LaunchTemplate",
    ),
    "Connection.Policy.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"assigned": "xdr"},
        requires_any=("Connection.Policy.Name",),
        resource="Policy",
    ),
    "Connection.Role.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"assigned": "xdr"},
        requires_any=("Connection.Role.Name",),
        resource="Role",
    ),
    "Connection.ServicePrincipal.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"create": "xdr", "delete": "xdr", "modified": "xdr"},
        requires_any=("Connection.ServicePrincipal.Name",),
        resource="ServicePrincipal",
    ),
    "Connection.SharingLink.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"created": "xdr"},
        requires_any=("Connection.SharingLink.Name",),
        resource="SharingLink",
    ),
    "Connection.SshKey.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"assigned": "xdr"},
        requires_any=("Connection.SshKey.Name",),
        resource="SshKey",
    ),
    "Connection.Url.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"downloaded": "xdr", "uploaded": "xdr", "delete": "xdr"},
        requires_any=("Connection.Url.Name",),
        resource="Url",
    ),
    "Connection.UserGroup.Operation": Field(
        target="connection",
        availability="xdr",
        relations=("is", "any"),
        kind="enum",
        values={"added": "xdr"},
        requires_any=("Connection.UserGroup.Name",),
        resource="UserGroup",
    ),
    "Registry.Key": Field(
        target="registry", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Registry.Value": Field(
        target="registry", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Registry.CreatedBy.Name": Field(
        target="registry", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Registry.CreatedBy.Path": Field(
        target="registry", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Registry.CreatedBy.FullPathName": Field(
        target="registry", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Registry.CreatedBy.CommandLine": Field(
        target="registry", availability="edr", relations=("is", "contains", "any"), kind="string"
    ),
    "Registry.Data": Field(
        target="registry",
        availability="edr",
        relations=("is", "contains", "any"),
        kind="string",
        requires_any=("Registry.DataType",),
    ),
    "Registry.Operation": Field(
        target="registry",
        availability="edr",
        relations=("is", "any"),
        kind="enum",
        values={
            "key_created": "edr",
            "key_deleted": "edr",
            "key_renamed": "edr",
            "value_created": "edr",
            "value_deleted": "edr",
            "value_written": "edr",
        },
    ),
    "Registry.DataType": Field(
        target="registry",
        availability="edr",
        relations=("is",),
        kind="enum",
        values={
            "string": "edr",
            "expandablestring": "edr",
            "dword": "edr",
            "qword": "edr",
            "binary": "edr",
            "none": "edr",
            "link": "edr",
            "resource_list": "edr",
            "full_resource_descriptor": "edr",
            "resource_requirements_list": "edr",
        },
    ),
}
