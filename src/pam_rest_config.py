from configparser import ConfigParser
from dataclasses import dataclass
from typing import Type, Union
import os

FILE_PATH = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = "config.ini"


@dataclass
class PamRestConfig:
	API_URL: str = ""
	UNSAFE_AUTH: bool = False
	RECV_EXPECTED: str = ""
	SEND_ENCRYPTED: str = ""
	PROMPT_LABEL: str = "Interlock IdP Password"
	TOTP_RETRY_LIMIT: int = 3


def get_config_parser(path: str | None = None) -> ConfigParser:
	if not path:
		path = os.path.join(FILE_PATH, CONFIG_FILE)
	config_parser = ConfigParser()
	config_parser.read(path)
	return config_parser


def get_config_parser_item(
	parser: ConfigParser,
	section_key: str,
	attr_key: str,
	attr_type: Type[Union[bool, int, float, str]] | None = None,
):
	if not isinstance(parser, ConfigParser):
		raise TypeError("parser must be of type ConfigParser")
	if section_key not in parser.sections():
		raise ValueError("section_key not in parser sections")

	# Get value from section
	section = parser[section_key]
	if attr_type is bool:
		return section.getboolean(attr_key, None)
	elif attr_type is int:
		return section.getint(attr_key, None)
	elif attr_type is float:
		return section.getfloat(attr_key, None)
	else:  # String value
		return section.get(attr_key, None)


def get_main_config() -> PamRestConfig:
	config_parser = get_config_parser()
	_pam_rest_config = PamRestConfig()

	if config_parser.has_section("MAIN"):
		for dataclass_field in PamRestConfig.__dataclass_fields__.keys():
			_default_v = getattr(_pam_rest_config, dataclass_field)
			if _default_v is not None:
				_v_type = type(_default_v)

			_v = get_config_parser_item(
				parser=config_parser,
				section_key="MAIN",
				attr_key=dataclass_field,
				attr_type=_v_type,
			)
			if _v is not None:
				setattr(_pam_rest_config, dataclass_field, _v)
	return _pam_rest_config


def get_user_shell_config() -> dict:
	config_parser = get_config_parser(
		path=os.path.join(FILE_PATH, "user_shells.ini")
	)
	if not config_parser.has_section("SHELLS"):
		return {}
	return dict(config_parser["SHELLS"])


PAM_REST_CONFIG = get_main_config()
USER_SHELL_CONFIG = get_user_shell_config()
DEFAULT_HEADERS = {
	"Content-Type": "application/json",
	"Accept": "application/json",
}
