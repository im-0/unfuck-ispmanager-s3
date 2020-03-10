import logging
import logging.handlers
import os.path
import sys

import click
import setproctitle

import unfispms3.patcher as patcher
import unfispms3.util as util


_DEFAULT_CACHE_FILE = os.path.join(
    os.path.expanduser('~'), '.local', 'share', 'unfispms3', 'radare2.cache')
# We only instrument executables matching this regex.
_DEFAULT_TARGET_PATH_RE_STR = r'^/usr/local/mgr5/.*$'

# TODO: optimize logging (remove f'aaa {xxx}' and use %-formatting).
_L = None


@click.command(
    name='analyze',
    help='Analyze a binary file using radare2.')
@click.argument(
    'file_name',
    type=click.Path(
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True))
@click.pass_obj
@util.sync_run_fn
async def _analyze(cache_settings, file_name):
    await patcher.check()

    result = await patcher.analyze(file_name, cache_settings)

    result = list(result.items())
    result.sort(key=lambda pair: pair[0])

    for orig_str, bin_strs in result:
        for bin_str in bin_strs:
            print(f'"{orig_str}" @ {bin_str.orig_addr}:')
            for xref in bin_str.xrefs:
                print(f'    {xref}')


@click.command(
    name='run',
    help='Run command with live patching.')
@click.option(
    '--domain',
    '-d',
    type=str,
    default=None,
    help='Override Amazon S3 domain name.')
@click.option(
    '--region',
    '-r',
    type=str,
    default=None,
    help='Override Amazon S3 region name.')
@click.option(
    '--target-re',
    '-t',
    type=str,
    default=_DEFAULT_TARGET_PATH_RE_STR,
    show_default=True,
    help='Only instrument executables matching this regex.')
@click.argument(
    'command',
    nargs=-1,
    type=str,
    required=True)
@click.pass_obj
@util.sync_run_fn
async def _run(cache_settings, domain, region, target_re, command):
    await patcher.check()
    await patcher.run(command, domain, region, target_re, cache_settings)


def _conv_log_level(level_str):
    """
    Convert string to numeric log level.

    :param level_str: Log level string.
    :return: Numeric log level.
    """

    return {
        'd': logging.DEBUG,
        'i': logging.INFO,
        'w': logging.WARNING,
        'e': logging.ERROR,
        'c': logging.CRITICAL,
    }[level_str[0]]


def _configure_logger(level='info', syslog=False):
    """
    Configure logger.

    :param level: Log level string.
    :param syslog: True to use syslog, False (default) to write log into stderr.
    """

    if syslog:
        log_format = '%(message)s'
        kwargs = dict(
            handlers=(
                logging.handlers.SysLogHandler(
                    address='/dev/log',
                    facility=logging.handlers.SysLogHandler.LOG_DAEMON), ))
    else:
        log_format = '%(asctime)s [%(levelname).1s] %(message)s'
        kwargs = dict(stream=sys.stderr)

    root_logger = logging.getLogger()
    list(map(root_logger.removeHandler, root_logger.handlers[:]))
    list(map(root_logger.removeFilter, root_logger.filters[:]))

    logging.basicConfig(
        format=log_format,
        level=_conv_log_level(level),
        **kwargs)

    global _L
    _L = logging.getLogger()


@click.group(
    context_settings={'help_option_names': ['-h', '--help']})
@click.option(
    '--log-level',
    '-l',
    type=click.Choice(
        ('debug', 'info', 'warning', 'error', 'critical'),
        case_sensitive=False),
    default='info',
    show_default=True,
    help='Log level.')
@click.option(
    '--syslog',
    '-s',
    is_flag=True,
    help='Write log into syslog instead of stderr.')
@click.option(
    '--cache-file',
    '-c',
    type=click.Path(
        exists=False,
        file_okay=True,
        dir_okay=False,
        writable=True),
    default=_DEFAULT_CACHE_FILE,
    show_default=True,
    help='Path to the file containing binary analysis cache.')
@click.option(
    '--no-cache',
    is_flag=True,
    help='Do not use existing values from cache.')
@click.option(
    '--no-cache-update',
    is_flag=True,
    help='Do not write new values into cache.')
@click.pass_context
def _main(ctx, log_level, syslog, cache_file, no_cache, no_cache_update):
    _configure_logger(log_level, syslog)

    ctx.obj = patcher.CacheSettings(
        cache_file=cache_file,
        use_cache=not no_cache,
        update_cache=not no_cache_update)


def main():
    """
    Program's entry point.
    """

    _configure_logger()

    setproctitle.setproctitle('unfispms3')

    _main.add_command(_analyze)
    _main.add_command(_run)

    _main(obj=None)


if __name__ == "__main__":
    main()
