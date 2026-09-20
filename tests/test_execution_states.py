"""Actual execution outcomes are independent of security judgments."""
from dataclasses import asdict
import json
import sys

import pytest

from sandbox.executors.api_executor import APIExecutor, ExecutionContext
from sandbox.executors.replay import ConversationReplayExecutor
from sandbox.executors.mcp import MCPExecutor
from sandbox.assertions import response_assertions


class Response:
    def __init__(self, status=200, value=None):
        self.status_code = status
        self.value = value or {'answer':'ok'}
        self.text = json.dumps(self.value)
    def json(self):
        return self.value


def test_replay_same_session_and_final_assertion(monkeypatch):
    replay = ConversationReplayExecutor()
    payloads = []
    def request(method, url, **kwargs):
        payloads.append(kwargs['json'])
        return Response()
    monkeypatch.setattr(replay.api_executor.session, 'request', request)
    r = replay.execute({'turns':[{'message':'one'}, {'message':'two'}],
                        'final_assertion': {'type':'json_path','value':'answer','equals':'ok'}})
    assert r.status == 'completed'
    assert payloads[0]['session_id'] == payloads[1]['session_id'] == r.conversation_id
    assert r.assertions[0]['status'] == 'pass'
    assert r.side_effects['exploitable'] is False


def test_http_second_turn_failure(monkeypatch):
    api = APIExecutor()
    replies = iter([Response(), Response(500)])
    monkeypatch.setattr(api.session, 'request', lambda *a, **kw: next(replies))
    r = api.execute({'multi_turn':True, 'turns':[{'message':'one'},{'message':'two'}]})
    assert not r.success
    assert r.status == 'error'
    assert len(r.output['history']) == 2


def test_replay_missing_injector_is_not_success():
    replay = ConversationReplayExecutor()
    r = replay.execute({'turns':[{'message':'hi','inject_before':[{'target':'missing'}]}]})
    assert not r.success and r.status == 'error'


def test_empty_turns_not_executed():
    assert ConversationReplayExecutor().execute({'turns':[]}).status == 'not_run'
    assert APIExecutor().execute({'multi_turn': True, 'turns':[]}).status == 'not_run'


def test_unknown_assertion_does_not_pass():
    r = response_assertions([{'type':'eval','value':'True'}], {}, 200)
    assert r[0]['status'] == 'unknown'


def test_json_path_is_not_substring():
    r = response_assertions([{'type':'json_path','value':'secret'}], {'note':'secret'}, 200)
    assert r[0]['status'] == 'fail'


def test_mcp_exit_does_not_hang(tmp_path):
    ex = MCPExecutor([sys.executable, '-c', 'raise SystemExit(1)'], cwd=tmp_path, timeout=0.3)
    try:
        r = ex.execute({'tool':'x'})
        assert r.status == 'error'
    finally:
        ex.teardown()
    assert ex.process is None


def test_mcp_timeout_cleans_child(tmp_path):
    ex = MCPExecutor([sys.executable, '-c', 'import time; time.sleep(20)'], cwd=tmp_path, timeout=0.1)
    try:
        r = ex.execute({'tool':'x'})
        assert r.status == 'timeout'
    finally:
        ex.teardown()
    assert ex.process is None


def test_mcp_tool_error_is_not_completed(monkeypatch):
    ex = MCPExecutor()
    monkeypatch.setattr(ex, 'call_tool', lambda *args: {'result': {'isError':True, 'content':[]}})
    result = ex.execute({'tool':'read_file'})
    assert result.status == 'error'
    assert not result.success


def test_malformed_assertion_is_unknown():
    assert response_assertions([{'value':'x'}], {}, 200)[0]['status'] == 'unknown'


@pytest.mark.parametrize('exception,status', [(TimeoutError, 'error')])
def test_api_partial_history_survives_later_error(monkeypatch, exception, status):
    api = APIExecutor()
    calls = []
    def request(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise exception('second turn failed')
        return Response(value={'answer':'first turn evidence'})
    monkeypatch.setattr(api.session, 'request', request)
    r = api.execute({'multi_turn':True, 'turns':[{'message':'first'}, {'message':'second'}]})
    assert r.status == status
    assert r.output['history'][0]['agent']['answer'] == 'first turn evidence'


def test_api_partial_history_survives_http_timeout(monkeypatch):
    import requests
    api = APIExecutor()
    calls = []
    def request(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise requests.Timeout('response timeout')
        return Response(value={'answer':'first turn evidence'})
    monkeypatch.setattr(api.session, 'request', request)
    r = api.execute({'multi_turn':True, 'turns':[{'message':'first'}, {'message':'second'}]})
    assert r.status == 'timeout'
    assert r.output['history'][0]['agent']['answer'] == 'first turn evidence'


def test_legacy_side_effect_probe_reports_failure(monkeypatch):
    api = APIExecutor()
    def fail(*args, **kwargs):
        raise OSError('receiver offline')
    monkeypatch.setattr(api.session,'get',fail)
    result = api.check_side_effects({'email_sent_to':'synthetic@example.test'})
    assert result['emails'] is None
    assert all(c['status']=='error' and not c['window_complete'] for c in result['collection'].values())


def test_http_cli_preserved_without_false_safety(tmp_path, monkeypatch, capsys):
    from sandbox.executors.api_executor import main, ExecutionResult
    graph=tmp_path/'graph.json'; graph.write_text(json.dumps({'test_cases':[{'id':'x'}]}))
    output=tmp_path/'result.json'
    monkeypatch.setattr(sys,'argv',['api_executor','--attack-graph',str(graph),'--output',str(output)])
    monkeypatch.setattr(APIExecutor,'execute',lambda *a: ExecutionResult(True,status='completed',output={'answer':'ok'}))
    assert main()==0
    record=json.loads(output.read_text())[0]
    assert record['security_verdict']=='inconclusive'
    assert record['exploitable'] is None


def test_mcp_command_string_keeps_windows_backslashes(monkeypatch):
    # Patch only the executor module's view of os.name: patching the global os.name
    # makes pathlib (<= 3.12) try to instantiate WindowsPath on POSIX and crash pytest.
    import types
    import sandbox.executors.mcp as mcp_module
    monkeypatch.setattr(mcp_module, 'os', types.SimpleNamespace(name='nt'))
    ex = MCPExecutor(r'C:\Users\me\python.exe -m testbeds.mcp_mini_server.server')
    assert ex.mcp_command == [r'C:\Users\me\python.exe', '-m', 'testbeds.mcp_mini_server.server']


def test_mcp_command_string_posix_quoting():
    assert MCPExecutor("python -m 'my server'").mcp_command == ['python', '-m', 'my server']


def test_cli_executor_reports_execution_status(tmp_path):
    from sandbox.executors.cli import CLIExecutor
    ok = CLIExecutor(f'{sys.executable} -c pass', cwd=tmp_path).execute({})
    assert ok.success and ok.status == 'completed'
    failed = CLIExecutor(f'{sys.executable} -c exit(3)', cwd=tmp_path).execute({})
    assert not failed.success and failed.status == 'error'
    slow = CLIExecutor(f"{sys.executable} -c __import__('time').sleep(5)", cwd=tmp_path).execute({'timeout': 0.2})
    assert not slow.success and slow.status == 'timeout'


def test_web_executor_reports_execution_status(monkeypatch):
    from sandbox.executors.web import WebExecutor
    import sandbox.executors.web as web
    class Element:
        def fill(self, *_): pass
        def press(self, *_): pass
        def inner_text(self): return 'agent reply'
    class Page:
        url = 'http://agent.test/'
        found = True
        def query_selector(self, *_): return Element() if self.found else None
        def wait_for_function(self, *a, **k): pass
        def query_selector_all(self, *_): return [Element()]
    monkeypatch.setattr(web.time, 'sleep', lambda *_: None)
    ex = WebExecutor(); monkeypatch.setattr(ex, '_init', lambda: None); ex.page = Page()
    assert ex.execute({'payload': {'message': 'hi'}}).status == 'completed'
    assert ex.execute({'multi_turn': True, 'turns': [{'message': 'a'}]}).status == 'completed'
    ex.page.found = False
    r = ex.execute({'payload': {'message': 'hi'}})
    assert not r.success and r.status == 'error'


def test_success_without_explicit_status_means_completed():
    from sandbox.executors.api_executor import ExecutionResult
    assert ExecutionResult(True).status == 'completed'
    assert ExecutionResult(False).status == 'not_run'
