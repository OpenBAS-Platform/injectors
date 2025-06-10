import subprocess

class NetExecProcess:

    @staticmethod
    def net_exec_version():
        subprocess.run(["NetExec"], capture_output=True, check=True)

    @staticmethod
    def net_exec_execute(args):
        return subprocess.run(args, capture_output=True, check=True)
