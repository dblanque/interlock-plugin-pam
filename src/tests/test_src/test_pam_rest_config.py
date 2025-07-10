########################### Standard Pytest Imports ############################
import pytest
from pytest_mock import MockerFixture
################################################################################
from configparser import ConfigParser
import os
from pam_rest_config import (
	FILE_PATH,
	CONFIG_FILE,
	get_config_parser,
	get_main_config,
	get_config_parser_item,
	get_user_shell_config,
)

@pytest.fixture
def mock_config_functions(
	mocker: MockerFixture,
	skip_patch: list[str] | str | None = None,
):
	if not skip_patch:
		skip_patch = []
	for k in (
		"get_config_parser",
		"get_main_config",
		"get_user_shell_config",
	):
		if k not in skip_patch:
			mocker.patch(f"pam_rest_config.{k}")

@pytest.fixture
def f_config_parser(mocker: MockerFixture):
	m_config_parser = mocker.Mock(name="m_config_parser", spec=ConfigParser)
	m_config_parser_cls = mocker.patch(
		"pam_rest_config.ConfigParser",
		return_value=m_config_parser
	)
	return m_config_parser, m_config_parser_cls

class TestGetConfigParser:
	def test_without_path(self, f_config_parser):
		m_config_parser, m_config_parser_cls = f_config_parser
		result = get_config_parser()
		assert result == m_config_parser
		m_config_parser.read.assert_called_once_with(
			os.path.join(FILE_PATH, CONFIG_FILE)
		)

	def test_with_path(self, f_config_parser):
		m_config_parser, m_config_parser_cls = f_config_parser
		result = get_config_parser("mock_path")
		assert result == m_config_parser
		m_config_parser.read.assert_called_once_with("mock_path")

class TestGetConfigParserItem:
	def test_raises_type_error(self):
		with pytest.raises(TypeError):
			get_config_parser_item(
				parser=None, # type: ignore
				section_key="mock_section",
				attr_key="mock_attr",
			)

	def test_raises_section_not_exists(self, mocker: MockerFixture):
		m_config_parser = mocker.Mock(spec=ConfigParser)
		m_config_parser.sections.return_value = []
		with pytest.raises(ValueError, match="not in parser"):
			get_config_parser_item(
				parser=m_config_parser, # type: ignore
				section_key="mock_section",
				attr_key="mock_attr",
			)

	@pytest.mark.parametrize(
		"target_fn_name, expected, test_type",
		(
			("get", "some_string", str),
			("get", "some_string", str),
			("getboolean", True, bool),
			("getint", 1, int),
			("getfloat", 1.5, float),
		)
	)
	def test_success_any(
		self,
		mocker: MockerFixture,
		target_fn_name: str,
		expected,
		test_type,
		mock_config_functions,
	):
		m_config_parser = mocker.Mock(spec=ConfigParser)
		# Mock return sections
		m_config_parser.sections.return_value = ["mock_section"]
		# Mock section get value type functions
		m_section = mocker.Mock()
		m_section.getboolean = mocker.Mock()
		m_section.getint = mocker.Mock()
		m_section.getfloat = mocker.Mock()
		m_section.get = mocker.Mock()
		target_fn = getattr(m_section, target_fn_name)
		target_fn.return_value = expected
		# Mock subscriptable getitem function
		m_config_parser.__getitem__ = mocker.Mock(return_value=m_section)

		# Assertions
		assert get_config_parser_item(
			parser=m_config_parser, # type: ignore
			section_key="mock_section",
			attr_key="mock_attr",
			attr_type=test_type
		) == expected

		m_config_parser.__getitem__.assert_called_once_with("mock_section")
		for fn in (
			"getboolean",
			"getint",
			"getfloat",
			"get",
		):
			if target_fn_name != fn:
				getattr(m_section, fn).assert_not_called()
		target_fn.assert_called_once_with("mock_attr", None)

class TestGetUserShellConfig:
	def test_empty_section(self, mocker: MockerFixture, f_config_parser):
		m_config_parser, m_config_parser_cls = f_config_parser
		m_config_parser.has_section.return_value = False
		m_get_config_parser = mocker.patch(
			"pam_rest_config.get_config_parser",
			return_value=m_config_parser
		)
		assert get_user_shell_config() == {}
		m_get_config_parser.assert_called_once_with(
			path=os.path.join(FILE_PATH, "user_shells.ini")
		)

	def test_section_as_dict(self, mocker: MockerFixture, f_config_parser):
		m_shell_conf = {"testuser":"/bin/false"}
		m_config_parser, m_config_parser_cls = f_config_parser
		m_config_parser.has_section.return_value = True
		m_config_parser.__getitem__ = mocker.Mock(return_value=m_shell_conf)

		m_get_config_parser = mocker.patch(
			"pam_rest_config.get_config_parser",
			return_value=m_config_parser
		)
		assert get_user_shell_config() == m_shell_conf
		m_get_config_parser.assert_called_once_with(
			path=os.path.join(FILE_PATH, "user_shells.ini")
		)