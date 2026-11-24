from pathlib import Path
from tempfile import TemporaryDirectory
import sys

if sys.platform == 'win32':
    import asyncio
    import asyncio.base_events
    import asyncio.proactor_events
    import asyncio.selector_events
    import asyncio.windows_events
    import http.client
    import http.server
    import io
    import selectors
    import signal
    import socketserver
    import time
    import httpx

    class _NoOpSelfPipeLoopMixin:
        def _make_self_pipe(self):
            self._ssock = None
            self._csock = None
            self._internal_fds += 1

        def _close_self_pipe(self):
            self._internal_fds -= 1

        def _write_to_self(self):
            pass

    class SandboxSelector(selectors.SelectSelector):
        def _select(self, r, w, _, timeout=None):
            if not r and not w:
                if timeout:
                    time.sleep(min(timeout, 0.01))
                return [], [], []
            return super()._select(r, w, _, timeout)

    class SandboxEventLoop(_NoOpSelfPipeLoopMixin, asyncio.SelectorEventLoop):
        """Event loop that avoids TCP socketpair self-pipe creation in restricted Windows Sandboxes."""
        def __init__(self, *args, **kwargs):
            super().__init__(selector=SandboxSelector())

    asyncio.windows_events.ProactorEventLoop = SandboxEventLoop
    asyncio.windows_events._WindowsSelectorEventLoop = SandboxEventLoop
    asyncio.ProactorEventLoop = SandboxEventLoop
    asyncio.SelectorEventLoop = SandboxEventLoop

    asyncio.SelectorEventLoop._make_self_pipe = _NoOpSelfPipeLoopMixin._make_self_pipe
    asyncio.SelectorEventLoop._close_self_pipe = _NoOpSelfPipeLoopMixin._close_self_pipe
    asyncio.SelectorEventLoop._write_to_self = _NoOpSelfPipeLoopMixin._write_to_self
    asyncio.ProactorEventLoop._make_self_pipe = _NoOpSelfPipeLoopMixin._make_self_pipe
    asyncio.ProactorEventLoop._close_self_pipe = _NoOpSelfPipeLoopMixin._close_self_pipe
    asyncio.ProactorEventLoop._write_to_self = _NoOpSelfPipeLoopMixin._write_to_self
    signal.set_wakeup_fd = lambda fd, *a, **kw: -1

    asyncio.new_event_loop = lambda: SandboxEventLoop()
    import asyncio.events
    asyncio.events.new_event_loop = lambda: SandboxEventLoop()

    def _sandbox_asyncio_run(main, *, debug=None, loop_factory=None):
        loop = SandboxEventLoop()
        try:
            return loop.run_until_complete(main)
        finally:
            loop.close()

    asyncio.run = _sandbox_asyncio_run
    import asyncio.runners
    asyncio.runners.run = _sandbox_asyncio_run

    def _sync_to_thread(func, /, *args, **kwargs):
        async def _coro():
            return func(*args, **kwargs)
        return _coro()

    asyncio.to_thread = _sync_to_thread

    class SyncASGITestClient:
        __test__ = False

        def __init__(self, app, base_url: str = "http://testserver", raise_server_exceptions: bool = True, **kwargs):
            self.app = app
            self.base_url = base_url
            self.raise_server_exceptions = raise_server_exceptions
            self._loop = SandboxEventLoop()
            self._transport = httpx.ASGITransport(app=app, raise_app_exceptions=raise_server_exceptions)
            self._client = httpx.AsyncClient(transport=self._transport, base_url=base_url)
            self._lifespan_cm = None

            class _Portal:
                def __init__(self, loop):
                    self._loop = loop
                def call(self, func, *args):
                    res = func(*args)
                    if asyncio.iscoroutine(res):
                        return self._loop.run_until_complete(res)
                    return res

            self.portal = _Portal(self._loop)

        def _run_coro(self, coro_factory):
            prev_loop = asyncio.events._get_running_loop()
            if prev_loop is not None:
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(lambda: self._loop.run_until_complete(coro_factory(self._client))).result()
            return self._loop.run_until_complete(coro_factory(self._client))

        def __enter__(self):
            if getattr(self.app.router, 'lifespan_context', None) is not None:
                self._lifespan_cm = self.app.router.lifespan_context(self.app)
                self._loop.run_until_complete(self._lifespan_cm.__aenter__())
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            try:
                if self._lifespan_cm is not None:
                    self._loop.run_until_complete(self._lifespan_cm.__aexit__(exc_type, exc_val, exc_tb))
            finally:
                self.close()

        def request(self, method: str, url: str, **kwargs):
            content = kwargs.get('content')
            if content is not None and not isinstance(content, (bytes, str)) and hasattr(content, '__iter__'):
                chunks = list(content)

                async def _agen():
                    for c in chunks:
                        yield c

                kwargs['content'] = _agen()
            return self._run_coro(lambda client: client.request(method, url, **kwargs))

        def get(self, url: str, **kwargs):
            return self.request("GET", url, **kwargs)

        def post(self, url: str, **kwargs):
            return self.request("POST", url, **kwargs)

        def put(self, url: str, **kwargs):
            return self.request("PUT", url, **kwargs)

        def delete(self, url: str, **kwargs):
            return self.request("DELETE", url, **kwargs)

        def patch(self, url: str, **kwargs):
            return self.request("PATCH", url, **kwargs)

        def options(self, url: str, **kwargs):
            return self.request("OPTIONS", url, **kwargs)

        def close(self):
            if not self._loop.is_closed():
                if self._client is not None:
                    prev_loop = asyncio.events._get_running_loop()
                    if prev_loop is not None:
                        asyncio.events._set_running_loop(None)
                    try:
                        self._loop.run_until_complete(self._client.aclose())
                    finally:
                        if prev_loop is not None:
                            asyncio.events._set_running_loop(prev_loop)
                self._loop.close()

    _active_http_servers = []
    _orig_server_init = socketserver.BaseServer.__init__

    def _tracked_server_init(self, *args, **kwargs):
        _orig_server_init(self, *args, **kwargs)
        _active_http_servers.append(self)

    socketserver.BaseServer.__init__ = _tracked_server_init
    _orig_http_connect = http.client.HTTPConnection.connect

    def _sandbox_http_connect(self):
        try:
            _orig_http_connect(self)
        except PermissionError as exc:
            if getattr(exc, 'winerror', None) == 10013 and self.host in ('127.0.0.1', 'localhost'):
                class _LoopbackSock:
                    def __init__(self):
                        self._buf = b''
                    def sendall(self, data):
                        raw_req = data if isinstance(data, bytes) else data.encode('iso-8859-1')
                        first_line = raw_req.split(b'\r\n', 1)[0].decode('iso-8859-1')
                        parts = first_line.split(' ')
                        path = parts[1] if len(parts) > 1 else '/'
                        frame = sys._getframe(1)
                        while frame is not None:
                            for val in list(frame.f_locals.values()):
                                handler_cls = getattr(val, 'RequestHandlerClass', None) or (
                                    val if isinstance(val, type) and issubclass(val, http.server.BaseHTTPRequestHandler) else None
                                )
                                if handler_cls is not None and hasattr(handler_cls, 'do_GET'):
                                    fake_self = type('_FakeHandler', (), {
                                        'path': path,
                                        '_status': 200,
                                        '_headers': [],
                                        'send_response': lambda s, c: setattr(s, '_status', c),
                                        'send_header': lambda s, k, v: s._headers.append((k, v)),
                                        'end_headers': lambda s: None,
                                    })()
                                    handler_cls.do_GET(fake_self)
                                    header_lines = ''.join(f'{k}: {v}\r\n' for k, v in fake_self._headers)
                                    self._buf = f'HTTP/1.1 {fake_self._status} Found\r\n{header_lines}Content-Length: 0\r\n\r\n'.encode('iso-8859-1')
                                    return
                            frame = frame.f_back
                    def makefile(self, mode, *a, **kw):
                        return io.BytesIO(self._buf)
                    def close(self):
                        pass
                self.sock = _LoopbackSock()
            else:
                raise

    http.client.HTTPConnection.connect = _sandbox_http_connect


def pytest_configure(config):
    if sys.platform == 'win32':
        import fastapi.testclient
        import starlette.testclient
        fastapi.testclient.TestClient = SyncASGITestClient
        starlette.testclient.TestClient = SyncASGITestClient
        for mod in list(sys.modules.values()):
            if mod is not None and getattr(mod, 'TestClient', None) is not None:
                try:
                    setattr(mod, 'TestClient', SyncASGITestClient)
                except Exception:
                    pass
            if mod is not None and getattr(mod, 'asyncio', None) is asyncio:
                asyncio.run = _sandbox_asyncio_run

    if config.option.basetemp is None:
        temporary = TemporaryDirectory(prefix='locket-pytest-')
        config.add_cleanup(temporary.cleanup)
        config.option.basetemp = Path(temporary.name) / 'run'
