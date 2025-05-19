import subprocess


class NucleiProcess:

    @staticmethod
    def nuclei_update_templates():
        subprocess.run(["nuclei", "-update-templates"], check=True)

    @staticmethod
    def nuclei_version():
        subprocess.run(["nuclei", "-version"], capture_output=True, check=True)

    @staticmethod
    def nuclei_execute(args, input_data):
        nuclei_args = ["nuclei"] + args
        return subprocess.run(
            nuclei_args, input=input_data, capture_output=True, check=True
        )


class NucleiArgsBuilder:
    def __init__(self):
        self.args = []

    def add_url(self, url):
        self.args += ["-u", url]
        return self

    def add_tags(self, tags):
        self.args += ["-tags", tags]
        return self

    def add_template(self, template):
        self.args += ["-t", template]
        return self

    def set_json_output(self):
        if "-j" not in self.args:
            self.args.append("-j")
        return self

    def build(self):
        return self.args
