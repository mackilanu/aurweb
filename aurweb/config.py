import configparser
import os

AURWEB_VERSION = "v5.0.0"

_parser = None


def _get_parser():
    global _parser

    if not _parser:
        path = os.environ.get('AUR_CONFIG', '/etc/aurweb/config')
        defaults = os.environ.get('AUR_CONFIG_DEFAULTS', path + '.defaults')

        _parser = configparser.RawConfigParser()
        if os.path.isfile(defaults):
            with open(defaults) as f:
                _parser.read_file(f)
        _parser.read(path)

    return _parser


def rehash():
    """ Globally rehash the configuration parser. """
    global _parser
    _parser = None
    _get_parser()


def get(section, option):
    return _get_parser().get(section, option)


def getboolean(section, option):
    return _get_parser().getboolean(section, option)


def getint(section, option):
    return _get_parser().getint(section, option)
