import contextlib
import logging
import re
import typing

import r2pipe


_L = logging.getLogger(__name__)

_OPCODE_TO_REG = (
    re.compile(r'^ *lea +(\w+) *,.*$'),
)


@contextlib.contextmanager
def _radare2_open(fname):
    """
    Context manager that automatically closes connection and terminates child
    radare2 process.

    :param fname: Path to binary file that should be analyzed using radare2.
    :return: Radare2/r2pipe client.
    """

    r2 = r2pipe.open(
        fname,
        flags=[
            '-2',  # Close stderr before starting RCore.
        ])
    try:
        yield r2
    finally:
        r2.quit()


def check():
    """
    Check that r2pipe is able to find and run radare2 executable.
    """

    with _radare2_open('--') as r2:
        r2_ver = r2.cmdJ('?Vj')
    _L.debug(f'Radare2 version: {r2_ver}')


class XRef(typing.NamedTuple):
    """
    Reference to string from code.
    """

    # Address of instruction that references string.
    pc: int
    # Length of instruction.
    len: int
    # Name of register that contains address of string after executing.
    reg: str


class BinString(typing.NamedTuple):
    """
    String found in binary.
    """

    # Address of string.
    orig_addr: int
    # References from code to this string.
    xrefs: typing.List[XRef]


def _opcode_to_reg(opcode):
    """
    Extract name of target register from disassembled opcode.
    :param opcode: Disassembled line.
    :return: Name of register.
    """

    for regexp in _OPCODE_TO_REG:
        match = regexp.match(opcode)
        if match is not None:
            return match.group(1)
    assert False, \
        f'Unsupported opcode: "{opcode}"'


def _find_strings(r2, strs_to_replace):
    """
    Find strings and code references in binary.
    :param r2: Instance of radare2/r2pipe client.
    :param strs_to_replace: Iterable of needed strings.
    :return: Dict containing all information required for live-patching.
    """

    r2_info = r2.cmdJ('ij')
    _L.debug(f'Binary info: {r2_info}')
    assert r2_info.core.format == 'elf64', \
        f'Unsupported binary format: "{r2_info.core.format}" != "elf64"'
    assert r2_info.bin.arch == 'x86', \
        f'Unsupported binary arch: "{r2_info.bin.arch}" != "x86"'
    assert r2_info.bin.bits == 64, \
        f'Unsupported binary bits: {r2_info.bin.bits} != 64'
    assert r2_info.bin.os == 'linux', \
        f'Unsupported binary os: "{r2_info.bin.os}" != "linux"'

    _L.info('Analyzing binary...')
    r2.cmd('aaa')

    _L.info('Searching for strings...')
    strs_found = {}
    for orig_str in strs_to_replace:
        _L.debug(f'Searching for string "{orig_str}"...')
        search_str = orig_str + '\0'
        search_str = search_str.encode('ascii').hex()

        r2_strs = r2.cmdJ(f'/xj {search_str}')
        _L.debug(f'Found strings: {r2_strs}')
        if not r2_strs:
            continue

        strs_found[orig_str] = []
        for r2_str in r2_strs:
            strs_found[orig_str].append(
                BinString(orig_addr=r2_str.offset, xrefs=[]))

    _L.info('Finding references to strings...')
    for orig_str, bin_strs in strs_found.items():
        for bin_str in bin_strs:
            # Use `cmdj()` instead of `cmdJ()` because `from` is reserved
            # in Python.
            vaddr = r2_info.bin.baddr + bin_str.orig_addr
            r2_xrefs = r2.cmdj(f'axtj {vaddr}')
            _L.debug(f'References for "{orig_str}": {r2_xrefs}')

            for r2_xref in r2_xrefs:
                _L.debug(f'Reference to "{orig_str}": {r2_xref}')
                pc = r2_xref['from']

                r2.cmd(f's {pc}')
                pc -= r2_info.bin.baddr

                r2_cur_section = r2.cmdJ('iSj.')
                _L.debug(f'Section: {r2_cur_section}')
                if r2_cur_section.name != '.text':
                    # Reference is not from code section.
                    continue

                r2_disasm = r2.cmdJ(f'pdj 1')
                _L.debug(f'Disasm: {r2_disasm}')
                assert len(r2_disasm) == 1, \
                    f'Unexpected length @{pc}: {r2_disasm}'
                r2_disasm = r2_disasm[0]

                xref = XRef(
                    pc=pc,
                    len=len(bytes.fromhex(r2_disasm.bytes)),
                    reg=_opcode_to_reg(r2_disasm.opcode))
                bin_str.xrefs.append(xref)

        bin_strs[:] = [
            bin_str
            for bin_str in bin_strs
            if bin_str.xrefs]
        assert bin_strs, \
            f'No valid references found for string "{orig_str}"'

    return strs_found


def find_strings(so_fname, strs_to_replace):
    """
    Find strings and code references in binary.

    :param so_fname: Path to binary file (*.so).
    :param strs_to_replace: Iterable of needed strings.
    :return: Dict containing all information required for live-patching.
    """

    _L.info(f'Opening "{so_fname}" in radare2...')
    with _radare2_open(so_fname) as r2:
        _L.debug('radare2 started')
        strs_found = _find_strings(r2, strs_to_replace)

    return strs_found
