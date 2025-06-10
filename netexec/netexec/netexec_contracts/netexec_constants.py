# -- CONFIG --
TYPE = "openbas_netexec"

# -- CONTRACTS --
# TODO: generate ID
SMB_SCAN_VULN_CONTRACT = ""
# TODO: add enumeration, etc

# -- FIELDS --
PROTOCOL_FIELD_KEY = "protocol"
IP_FIELD_KEY = "ip"
USER_FIELD_KEY = "user"
PASSWORD_FIELD_KEY = "password"
MODULE_FIELD_KEY = "module"

# -- VALUES --
PROTOCOL_SMB = "smb"
PROTOCOL_FIELD_VALUES = [PROTOCOL_SMB, "ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"]
