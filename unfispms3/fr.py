import asyncio
import collections
import functools
import json
import logging
import os
import re
import time

import frida

import unfispms3.util as util


_L = logging.getLogger(__name__)

# Target library for live-patching.
_SO_RE_STR = r'^libmgr.so($|\..*$)'

# How long to wait when no attached processes left before exiting.
_SETTLE_TIME = 4.0  # seconds


# Information about loded library:
#    base_addr: Base address of mapping.
#    size: Total size of mappings.
#    path: Path to *.so.
_Lib = collections.namedtuple(
    '_Lib', ('base_addr', 'size', 'path'))


class _Patcher:
    """
    Information about live patching script loaded into instrumented process.
    """

    def __init__(self):
        # True if script is already loaded.
        self.loaded = False
        # Set of already patched libraries (to not patch again).
        self.patched_libs = None
        # Addresses of strings loaded into memory of process.
        self.loaded_strings = None
        # RPC calls to perform live-patching.
        self.rpc = None


# TODO: Lock for concurrent access from different threads?
# Infromation about instrumented process.
#    path: Path to executable.
#    pid: PID.
#    session: Frida's session object.
#    patcher: Instance of _Patcher.
_Proc = collections.namedtuple(
    '_Proc', ('path', 'pid', 'session', 'patcher'))


def _get_abs_exe_path(path, pid):
    """
    Get absolute path to executable based on given path from Frida or `argv`
    and PID.

    :param path: Path from Frida or `argv`, may be None.
    :param pid: Process ID.
    :return: Absolute path to executable.
    """

    if path is None:
        # When origin == 'fork'.
        path = os.readlink(f'/proc/{pid}/exe')
    if not os.path.isabs(path):
        path = os.path.join(os.readlink(f'/proc/{pid}/cwd'), path)
    return os.path.abspath(path)


def _frida_callback_fn(fn):
    """
    Decorator to allow calling asynchronous functions from synchronous code
    in separate thread.

    Synchronous caller is not blocked, and there is no way to return
    anything to caller.

    :param fn: Asynchronous function. Should have `self` pointing to the
    instance of _Frida as the first argument.
    :return: Synchronous function.
    """

    @functools.wraps(fn)
    def _wrapper(self, *args, **kwargs):
        asyncio.run_coroutine_threadsafe(
            fn(self, *args, **kwargs),
            self._event_loop)

    return _wrapper


class _Frida:
    """
    Main process tracking / live patching all-in-one facility.
    """

    def __init__(self, replacements, target_re, analyze_fn):
        """
        Initialize process tracking / live patching.

        :param replacements: Dict {original string => replacement string}.
        :param target_re: Only instrument executables matching this regex
        string.
        :param analyze_fn: Function that should analyze library given by path
        and return found references to strings from library code.
        """

        self._replacements = replacements
        self._target_re = re.compile(target_re)
        self._analyze_fn = analyze_fn

        self._event_loop = asyncio.get_event_loop()

        self._device = None

        self._processes = {}
        self._processes_mtime = 0.0

    async def _run_one_msg_script(self, session, script):
        """
        Run JavaScript that sends back exactly one message.

        :param session: Frida's Session object.
        :param script: Script, string.
        :return: Message sent by script.
        """

        script = await util.async_run(session.create_script, script)

        msg_future = self._event_loop.create_future()

        def _callback(message, _):
            script.off('message', _callback)
            self._event_loop.call_soon_threadsafe(
                msg_future.set_result, message)

        script.on('message', _callback)

        # TODO: Unload script after use?
        await util.async_run(script.load)

        return await msg_future, script

    @_frida_callback_fn
    async def _on_patcher_message(self, proc, message):
        """
        Called on error message sent by patcher script.

        :param proc: _Proc object.
        :param message: Message dict from Frida.
        """

        assert message['type'] == 'send', \
            f'Unexpected message in _on_patcher_message(): {message}'
        message = message['payload']
        _L.error(f'Patcher error in {proc.pid}: {message}')

    async def _load_patcher(self, proc):
        """
        Load JavaScript code that allocates strings and provides RPC call to
        patch code of target libraries.

        :param proc: _Proc object.
        """

        _L.debug(f'Loading patcher into memory of {proc.pid}...')

        strings = json.dumps(list(self._replacements.items()))
        script = f'''
            rpc.exports = {{
                patch: function(pc, reg, orig_addr, replacement_addr) {{
                    pc = ptr(pc);
                    orig_addr = ptr(orig_addr);
                    replacement_addr = ptr(replacement_addr);
                    Interceptor.attach(pc, function(_args) {{
                        if (this.context[reg].equals(orig_addr)) {{
                            this.context[reg] = replacement_addr;
                        }} else {{
                            send(reg + ' != ' + orig_addr + ' at ' + pc);
                        }}
                    }});
                }}
            }};

            var strings = {{}};
            var allocated_strs = [];
            {strings}.forEach(function(pair) {{
                var allocated_str = Memory.allocUtf8String(pair[1]);
                strings[pair[0]] = allocated_str.toString(10);

                // Prevent strings from being freed.
                allocated_strs.push(allocated_str);
            }});
            send(strings);
        '''
        message, script = await self._run_one_msg_script(proc.session, script)
        assert message['type'] == 'send', \
            f'Unexpected message in _load_patcher(): {message}'

        strings = message['payload']
        proc.patcher.loaded_strings = dict(
            (one_string, int(addr))
            for one_string, addr in strings.items())
        _L.debug(f'String addresses in {proc.pid}:'
                 f' {proc.patcher.loaded_strings}')

        script.on('message', lambda m, _: self._on_patcher_message(proc, m))

        proc.patcher.patched_libs = set()
        proc.patcher.rpc = script.exports
        proc.patcher.loaded = True

    @util.async_run_fn
    def _patch_library(self, proc, library, bin_strs_dict):
        """
        Live patch code in one library.

        :param proc: _Proc object.
        :param library: _Lib object.
        :param bin_strs_dict: Dict containing references from library code
        to string addresses.
        """

        _L.debug(f'Patching {library} in {proc.pid}...')

        for orig_str, replacement_addr in proc.patcher.loaded_strings.items():
            bin_strs = bin_strs_dict.get(orig_str)
            if bin_strs is None:
                continue

            for bin_str in bin_strs:
                for xref in bin_str.xrefs:
                    pc = str(library.base_addr + xref.pc + xref.len)
                    orig_addr = str(library.base_addr + bin_str.orig_addr)
                    proc.patcher.rpc.patch(
                        pc, xref.reg, orig_addr, str(replacement_addr))

    async def _patch_libraries(self, proc, libraries):
        """
        Live patch libraries.

        :param proc: _Proc object.
        :param libraries: List of libraries returned from Frida.
        """

        if not libraries:
            # No libraries matching target regexp.
            return

        if not proc.patcher.loaded:
            # Assume that process containing our target library will not spawn
            # any other processes that require patching.
            # TODO: Why this leads to hang?
            #proc.session.disable_child_gating()

            await self._load_patcher(proc)

        for library in libraries:
            library = _Lib(
                base_addr=int(library['base'], 16),
                size=library['size'],
                path=library['path'])

            # We assume that loaded library can be uniquely identified by
            # base address, size and full path.
            if library in proc.patcher.patched_libs:
                _L.debug(f'Skipping {library} in {proc.pid}: already patched')
                continue

            bin_strs_dict = await self._analyze_fn(library.path)
            missing_xrefs = frozenset(proc.patcher.loaded_strings.keys()) \
                - frozenset(bin_strs_dict.keys())
            if missing_xrefs:
                _L.warning(f'Missing code references to some strings in'
                           f' {proc.pid} ({library.path}): {missing_xrefs}')

            await self._patch_library(proc, library, bin_strs_dict)
            proc.patcher.patched_libs.add(library)

    @_frida_callback_fn
    async def _on_dlopen_message(self, proc, script, message):
        """
        This callback is called on `dlopen()`.

        :param proc: _Proc object.
        :param script: Frida's Script object.
        :param message: Message dict. Contains thread ID and the list of
        modules matching target regexp.
        """

        assert message['type'] == 'send', \
            f'Unexpected message in _on_dlopen_message(): {message}'

        libraries = message['payload']['modules']
        thread_id = message['payload']['thread_id']
        _L.debug(
            f'Matching libraries after dlopen() in process {proc.pid},'
            f' thread {thread_id}: {libraries}')
        await self._patch_libraries(proc, libraries)

        # Unblock dlopen().
        await util.async_run(
            script.post,
            {'type': f'thread_{thread_id}', 'payload': None})

    @util.async_run_fn
    def _hook_dlopen(self, proc):
        """
        Hook `dlopen()` to check dynamically loaded libraries.

        :param proc: _Proc object.
        """

        script = f'''
            Interceptor.attach(Module.findExportByName(null, "dlopen"), {{
                onLeave: function(_ret) {{
                    var modules = new ModuleMap(function(module) {{
                        return module['name'].search(/{_SO_RE_STR}/) >= 0;
                    }}).values();

                    if (modules.length) {{
                        send({{
                            thread_id: this.threadId,
                            modules: modules
                        }});

                        var msg_type = 'thread_' + this.threadId;
                        // Do not return from dlopen() until patching is
                        // finished.
                        recv(msg_type, function(_value) {{}}).wait();
                    }};
                }}
            }});
        '''
        script = proc.session.create_script(script)
        script.on(
            'message',
            lambda m, _: self._on_dlopen_message(proc, script, m))
        script.load()

    async def _check_existing_libraries(self, proc):
        """
        Check already loaded libraries. This should be done right after exec().

        :param proc: _Proc object.
        """

        script = f'''
            var modules = new ModuleMap(function(module) {{
                return module['name'].search(/{_SO_RE_STR}/) >= 0;
            }}).values();
            send(modules);
        '''
        message, _ = await self._run_one_msg_script(proc.session, script)

        assert message['type'] == 'send', \
            f'Unexpected message in _check_existing_libraries(): {message}'

        libraries = message['payload']
        _L.debug(f'Matching libraries in process {proc.pid}: {libraries}')
        await self._patch_libraries(proc, libraries)

    @_frida_callback_fn
    async def _on_detached(self, proc, reason):
        """
        This called when Frida detaches from process.

        :param proc: _Proc object.
        :param reason: Detach reason, string.
        """

        _L.debug(f'Detached from {proc.pid}: {reason}')
        self._processes.pop(proc.session)
        self._processes_mtime = time.time()
        if not self._processes:
            _L.debug('No attached processes, waiting few seconds before'
                     ' giving up...')

    async def _instrument(self, pid, origin, path, first):
        """
        Attach Frida to process.

        :param pid: PID.
        :param origin: Origin: 'fork', 'exec' (not sure about other
        possibilities).
        :param path: Path to executable. May be None.
        :param first: True if this is the entry process (root of the process
        tree).
        """

        path = _get_abs_exe_path(path, pid)

        is_possible_target = self._target_re.match(path) is not None
        if is_possible_target or first:
            # Always attach to first (root) process in the process tree
            # to make sure that main loop will run at least as long as
            # first process is running

            _L.debug(f'Attaching to {pid} ({path})')
            proc = _Proc(
                path=path,
                pid=pid,
                session=await util.async_run(self._device.attach, pid),
                patcher=_Patcher())
            self._processes[proc.session] = proc
            self._processes_mtime = time.time()

            proc.session.on('detached', lambda r: self._on_detached(proc, r))

            if is_possible_target:
                proc.session.enable_child_gating()

                await self._hook_dlopen(proc)
                # Loaded libraries are the same after fork(), no need to
                # check/patch again after fork.
                if origin != 'fork':
                    await self._check_existing_libraries(proc)

        self._device.resume(pid)

    @_frida_callback_fn
    async def _on_child_added(self, child):
        """
        Frida calls this callback when new process spawned as child to one of
        already known processes.

        :param child: Child object.
        """

        _L.debug(f'Child added: {child.pid}, {child.origin}, {child.argv}')
        await self._instrument(child.pid, child.origin, child.path, False)

    @_frida_callback_fn
    async def _on_child_removed(self, child):
        """
        Known child process terminated.

        :param child: Child object.
        """
        _L.debug(f'Child removed: {child.pid}, {child.origin}, {child.argv}')

    async def _wait_until_no_processes(self):
        """
        Wait until no processes attached / detached for `_SETTLE_TIME` seconds.
        """

        _L.info('Starting main loop')
        while self._processes or \
                ((time.time() - self._processes_mtime) < _SETTLE_TIME):
            await asyncio.sleep(1.0)
        _L.info('Main loop finished')

    async def run(self, command):
        """
        Run process tracking.

        :param command: `argv` for entry executable.
        """

        self._device = frida.get_local_device()
        self._device.on('child-added', self._on_child_added)
        self._device.on('child-removed', self._on_child_removed)

        _L.info(f'Running {command}...')
        pid = await util.async_run(self._device.spawn, command)
        await self._instrument(pid, 'exec', command[0], True)

        await self._wait_until_no_processes()


async def run(command, replacements, target_re, analyze_fn):
    """
    Run command with instrumentation and live-patching.

    :param command: `argv` for entry executable.
    :param replacements: Dict {original string => replacement string}.
    :param target_re: Only instrument executables matching this regex string.
    :param analyze_fn: Function that should analyze library given by path
    and return found references to strings from library code.
    """

    _L.debug(f'Replacements: {replacements}')

    await _Frida(replacements, target_re, analyze_fn).run(command)
