from configparser import ConfigParser
from dataclasses import dataclass
import os

FILE_PATH = os.path.dirname(os.path.realpath(__file__))


@dataclass
class PamRestConfig:
	API_URL: str = ""
	UNSAFE_AUTH: bool = False
	RECV_EXPECTED: str = ""
	SEND_ENCRYPTED: str = ""
	PROMPT_LABEL: str = "Interlock IdP Password"


PAM_REST_CONFIG = PamRestConfig()
config_parser = ConfigParser()
config_parser.read(os.path.join(FILE_PATH, "pam_rest_auth_conf.ini"))
main_section = config_parser["MAIN"]
for attr in PamRestConfig.__dataclass_fields__.keys():
	if isinstance(getattr(PAM_REST_CONFIG, attr), bool):
		_v = main_section.getboolean(attr, None)
	else:
		_v = main_section.get(attr, None)
	if _v is not None:
		setattr(PAM_REST_CONFIG, attr, _v)

DEFAULT_HEADERS = {
	"Content-Type": "application/json",
	"Accept": "application/json",
}
