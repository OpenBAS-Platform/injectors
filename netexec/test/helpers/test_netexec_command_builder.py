from unittest import TestCase

from netexec.helpers.netexec_command_builder import NetExecCommandBuilder
from netexec.netexec_contracts.netexec_constants import SMB_SCAN_VULN_CONTRACT, IP_FIELD_KEY, USER_FIELD_KEY, PASSWORD_FIELD_KEY, \
    MODULE_FIELD_KEY


class NetExecCommandBuilderTest(TestCase):

    def test_smb_contract(self):
        content = {
            IP_FIELD_KEY: "localhost",
            USER_FIELD_KEY: "user",
            PASSWORD_FIELD_KEY: "pwd",
            MODULE_FIELD_KEY: "zerologon"
        }
        args = NetExecCommandBuilder.build_args(SMB_SCAN_VULN_CONTRACT, content)
        expected_args = ["nxc", "smb", "localhost", "-u", "user", "-p", "pwd", "-M", "zerologon"]
        self.assertEqual(args, expected_args)
