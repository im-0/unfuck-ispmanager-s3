import collections
import hashlib
import itertools
import json
import logging
import os
import typing

import atomicwrites
import typedload

import unfispms3.fr as fr
import unfispms3.r2 as r2
import unfispms3.util as util


_L = logging.getLogger(__name__)

# Cache settings:
#    cache_file: Path to file containing cached data.
#    use_cache: Try to find information about binary in cache before analyzing
#        it again.
#    update_cache: Write data into cache after analyzing previously unknown
#        binary.
CacheSettings = collections.namedtuple(
    'CacheSettings', ('cache_file', 'use_cache', 'update_cache'))
_Replacement = collections.namedtuple('_Replacement', ('fn', ))


_REPLACE_DOMAIN = {
    's3.amazonaws.com': _Replacement(
        fn=lambda d: d,
    ),

    '.s3.amazonaws.com/': _Replacement(
        fn=lambda d: f'.{d}/',
    ),

    '.s3.amazonaws.com': _Replacement(
        fn=lambda d: f'.{d}',
    ),

    'https://s3.amazonaws.com/': _Replacement(
        fn=lambda d: f'https://{d}/',
    ),
}

_REPLACE_REGION = {
    'us-east-1': _Replacement(
        fn=lambda r: r,
    ),
}


@util.async_run_fn_1thr
def check():
    """
    Sanity check environment.
    """

    r2.check()


# r2pipe.open_async is much more difficult to use in a case of multiple
# simultaneous radare2 instances because it tries to create its own
# event loop on each open().
@util.async_run_fn_1thr
def analyze(so_fname, cache_settings):
    """
    Try to find strings and references to them from code in binary file (*.so).

    :param so_fname: Path to binary.
    :param cache_settings: Instance of CacheSettings.
    :return: Dict containing all information required for live-patching.
    """

    strs_to_replace = frozenset(
        itertools.chain(_REPLACE_DOMAIN.keys(), _REPLACE_REGION.keys()))

    # TODO: Use lock file to prevent simultaneous read/write of cache file from
    # different threads or processes.
    _L.info(f'Reading cache from "{cache_settings.cache_file}"...')
    try:
        with open(cache_settings.cache_file, 'r') as cache_f:
            cache = typedload.load(
                json.load(cache_f),
                typing.Dict[str, typing.Dict[str, typing.List[r2.BinString]]])
    except FileNotFoundError:
        cache = {}

    _L.debug(f'Calculating sha512("{so_fname}")...')
    with open(so_fname, 'rb') as so_f:
        so_sha512 = hashlib.sha512(so_f.read()).hexdigest()
    _L.info(f'sha512("{so_fname}") == "{so_sha512}"')

    if cache_settings.use_cache:
        strings = cache.get(so_sha512)
    else:
        strings = None

    if strings is None:
        _L.info('Binary not found in cache (slow path)')
        strings = r2.find_strings(so_fname, strs_to_replace)

        if cache_settings.update_cache:
            _L.info(f'Writing cache into "{cache_settings.cache_file}"...')

            cache[so_sha512] = strings

            cache_file_dir = os.path.dirname(cache_settings.cache_file)
            os.makedirs(cache_file_dir, mode=0o700, exist_ok=True)

            with atomicwrites.atomic_write(
                    cache_settings.cache_file,
                    overwrite=True) as cache_f:
                json.dump(typedload.dump(cache), cache_f)
    else:
        _L.info('Using cached values')

    n_xrefs = sum(
        len(bin_str.xrefs)
        for bin_strs in strings.values()
        for bin_str in bin_strs)
    _L.info(f'Found {n_xrefs} references to strings in "{so_fname}"')
    _L.debug(f'References: {strings}')

    return strings


async def run(command, domain, region, target_re, cache_settings):
    """
    Run command with live-patching.

    :param command: `argv` for entry executable.
    :param domain: Override hard-coded Amazon S3 domain name with this string.
    :param region: Override hard-coded Amazon S3 region name with this string.
    :param target_re: Only instrument executables matching this regex string.
    :param cache_settings: Instance of CacheSettings.
    """

    # TODO: Propagate signals to child processes.
    # TODO: Terminate on errors from threads.
    replacements = {}

    if domain is not None:
        assert domain.isascii(), \
            f'Domain is not ASCII: "{domain}"'
        replacements.update(
            (orig, rep.fn(domain))
            for orig, rep in _REPLACE_DOMAIN.items())

    if region is not None:
        assert region.isascii(), \
            f'Region is not ASCII: "{region}"'
        replacements.update(
            (orig, rep.fn(region))
            for orig, rep in _REPLACE_REGION.items())

    return await fr.run(
        command, replacements, target_re, lambda s: analyze(s, cache_settings))
