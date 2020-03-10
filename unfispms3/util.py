import asyncio
import concurrent.futures
import functools


_SHARED_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def sync_run_fn(fn):
    """
    Decorator to synchronously run asynchronous function.

    :param fn: Asynchronous function.
    :return: Synchronous function.
    """

    loop = asyncio.get_event_loop()

    @functools.wraps(fn)
    def _wrapper(*args, **kwargs):
        return loop.run_until_complete(fn(*args, **kwargs))

    return _wrapper


def async_run_fn_1thr(fn):
    """
    Decorator to asynchronously run synchronous function in its own separate
    thread.

    :param fn: Synchronous function.
    :return: Asynchronous function.
    """

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop = asyncio.get_event_loop()

    @functools.wraps(fn)
    def _wrapper(*args, **kwargs):
        return loop.run_in_executor(
            executor,
            functools.partial(fn, *args, **kwargs))

    return _wrapper


def async_run_fn(fn):
    """
    Decorator to asynchronously run synchronous function in shared thread pool.

    :param fn: Synchronous function.
    :return: Asynchronous function.
    """

    loop = asyncio.get_event_loop()

    @functools.wraps(fn)
    def _wrapper(*args, **kwargs):
        return loop.run_in_executor(
            _SHARED_EXECUTOR,
            functools.partial(fn, *args, **kwargs))

    return _wrapper


def async_run(fn, *args, **kwargs):
    """
    Run synchronous function in shared thread pool.

    :param fn: Synchronous function.
    :param args:
    :param kwargs:
    :return: Asynchronous result.
    """

    loop = asyncio.get_event_loop()
    return loop.run_in_executor(
        _SHARED_EXECUTOR,
        functools.partial(fn, *args, **kwargs))
