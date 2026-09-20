"""Bundle integrity, comparison invariants and real local MCP effects."""
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path

import pytest

from sandbox.contracts import load_json, write_json_new, canonical_hash
from sandbox.correlation import VerdictEngine
from sandbox.regression import compare, read_run, rejudge, fingerprints, normal_ok
from sandbox.test_runner import run_suite, judge_verdict

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples/regression'


@pytest.fixture(scope='module')
def pair(tmp_path_factory):
    root = tmp_path_factory.mktemp('paired')
    suite = load_json(EXAMPLES / 'suite.json')
    for name in ('vulnerable', 'fixed'):
        run_suite(suite, load_json(EXAMPLES / f'{name}.json'), root / name)
    return root


def copy_run(pair, tmp_path, name='fixed'):
    import shutil
    dest = tmp_path / name
    shutil.copytree(pair / name, dest)
    return dest


def edit_manifest(root, callback):
    import json
    path = root / 'manifest.json'
    data = load_json(path); callback(data)
    path.write_text(json.dumps(data))


def test_real_pair_has_effects_and_working_controls(pair):
    result = compare(pair / 'vulnerable', pair / 'fixed')
    assert result['exit_code'] == 0
    assert result['remediation_passed'] == 6
    assert result['before']['confirmed_effects'] == 6
    assert result['after']['confirmed_effects'] == 0
    assert result['before']['normal_passed'] == result['after']['normal_passed'] == 6
    assert result['after']['execution_failures'] == 0
    _, raw = read_run(pair / 'fixed')
    for e in raw:
        VerdictEngine().judge(e)
        if e.metadata['group'] == 'proxy':
            assert all(a['status'] == 'fail' for a in e.assertions if a['kind'] == 'impact')
        assert e.execution['status'] == 'completed'


def test_shared_decision_entry(pair):
    _, raw = read_run(pair / 'vulnerable')
    for ev in raw:
        old = judge_verdict(asdict(ev))
        assert old['canonical_verdict'] == VerdictEngine().judge(ev).verdict


def test_rejudge_does_not_touch_input(pair, tmp_path):
    from sandbox.contracts import file_hash
    source = pair / 'vulnerable'
    before = {p: file_hash(p) for p in source.rglob('*.json')}
    first = rejudge(source, tmp_path / 'first')
    second = rejudge(source, tmp_path / 'second')
    assert first == second
    assert {p: file_hash(p) for p in before} == before
    assert load_json(tmp_path/'first/provenance.json')['operation'] == 'rejudge_not_rerun'


def test_repeat_output_rejected(pair):
    with pytest.raises(FileExistsError):
        run_suite(load_json(EXAMPLES/'suite.json'), load_json(EXAMPLES/'fixed.json'), pair/'fixed')


def test_rejudge_output_rejected(pair, tmp_path):
    (tmp_path/'existing').mkdir()
    with pytest.raises(FileExistsError):
        rejudge(pair/'fixed', tmp_path/'existing')


@pytest.mark.parametrize('field', ['analyzer', 'collector', 'fixture', 'environment', 'invariants'])
def test_comparison_drift_rejected(pair, tmp_path, field):
    root = copy_run(pair, tmp_path)
    edit_manifest(root, lambda m: m['comparison'].__setitem__(field, 'drift'))
    result = compare(pair/'vulnerable', root)
    assert result['status'] == 'NOT_COMPARABLE'
    assert result['exit_code'] == 2


def test_undeclared_fix_rejected(pair, tmp_path):
    root = copy_run(pair, tmp_path)
    edit_manifest(root, lambda m: m.pop('remediation'))
    assert compare(pair/'vulnerable', root)['status'] == 'NOT_COMPARABLE'


def test_missing_inventory_not_partial_success(pair, tmp_path):
    root = copy_run(pair, tmp_path)
    edit_manifest(root, lambda m: m['records'].pop())
    with pytest.raises(ValueError, match='inventory'):
        compare(pair/'vulnerable', root)


def test_corrupt_raw_refused(pair, tmp_path):
    root = copy_run(pair, tmp_path)
    record = load_json(root/'manifest.json')['records'][0]
    (root/record['raw']).write_text('{}')
    with pytest.raises(ValueError, match='hash mismatch'):
        compare(pair/'vulnerable', root)


def test_path_escape_refused(pair, tmp_path):
    root = copy_run(pair, tmp_path)
    edit_manifest(root, lambda m: m['records'][0].__setitem__('raw', '../outside.json'))
    with pytest.raises(ValueError, match='artifact'):
        read_run(root)


def test_unknown_schema_refused(pair, tmp_path):
    root = copy_run(pair, tmp_path)
    edit_manifest(root, lambda m: m.__setitem__('schema_version', 42))
    with pytest.raises(ValueError):
        read_run(root)


def test_no_positive_baseline_does_not_claim_fixed(pair):
    result = compare(pair/'fixed', pair/'fixed')
    assert result['exit_code'] == 2
    assert result['remediation_passed'] == 0
    assert any(r['result'] == 'NO_POSITIVE_BASELINE' for r in result['rows'])


def test_still_vulnerable_fails_gate(pair):
    result = compare(pair/'vulnerable', pair/'vulnerable')
    assert result['exit_code'] == 1
    assert any(r['result'] == 'STILL_EXPLOITABLE' for r in result['rows'])


def test_disabling_tools_not_a_fix(tmp_path):
    suite = load_json(EXAMPLES/'suite.json')
    suite['cases'] = [suite['cases'][0], suite['cases'][3]]
    before = load_json(EXAMPLES/'vulnerable.json')
    disabled = {**before, 'variant': 'disabled', 'remediation': {
        'from_variant':'vulnerable', 'to_variant':'disabled', 'description':'disable all tools'}}
    run_suite(suite, before, tmp_path/'before')
    run_suite(suite, disabled, tmp_path/'after')
    result = compare(tmp_path/'before', tmp_path/'after')
    assert result['exit_code'] == 1
    assert result['remediation_passed'] == 0
    assert any(r['result'] == 'FUNCTIONAL_REGRESSION' for r in result['rows'])


def test_lost_collector_stays_unknown(monkeypatch, tmp_path):
    from sandbox.executors.mcp import MCPExecutor
    from sandbox.executors.api_executor import ExecutionResult
    from sandbox.test_runner import run_mcp_case
    monkeypatch.setattr(MCPExecutor, 'execute', lambda *a: ExecutionResult(False, status='timeout', error='injected timeout'))
    case = load_json(EXAMPLES/'suite.json')['cases'][0]
    ev = run_mcp_case(case, load_json(EXAMPLES/'fixed.json'), 'fault-run')
    assert VerdictEngine().judge(ev).verdict == 'inconclusive'
    assert ev.execution['status'] == 'timeout'
    assert ev.collection['response']['status'] == 'error'


def test_legacy_failure_explicit(monkeypatch):
    import sandbox.test_runner as runner
    def failed(*a, **kw):
        raise OSError('collector disconnected')
    monkeypatch.setattr(runner.requests, 'get', failed)
    result = runner.fetch_mailhog_messages()
    assert result['status'] == 'error'
    assert result['data'] is None
    assert judge_verdict({'logs': {'mail': result}})['result'] == 'inconclusive'


def test_duplicate_json_keys_refused(tmp_path):
    path = tmp_path/'invalid.json'; path.write_text('{"a": 1, "a": 2}')
    with pytest.raises(ValueError):
        load_json(path)


def test_schema_matches_all_serialized_records(pair):
    import jsonschema
    schema = load_json(Path(__file__).resolve().parents[1]/'sandbox/evidence.schema.json')
    for name in ('vulnerable','fixed'):
        _, raw = read_run(pair/name)
        for ev in raw:
            jsonschema.validate(asdict(VerdictEngine().judge(ev)), schema)


def test_profile_cannot_claim_model_run(tmp_path):
    profile = load_json(EXAMPLES/'fixed.json'); profile['model'] = 'not-actually-used'
    with pytest.raises(ValueError, match='LLM'):
        run_suite(load_json(EXAMPLES/'suite.json'), profile, tmp_path/'bad')


def test_mutated_derived_result_cannot_change_comparison(pair, tmp_path):
    import json
    from sandbox.contracts import file_hash
    root = copy_run(pair, tmp_path)
    manifest = load_json(root/'manifest.json')
    path = root/manifest['records'][0]['judged']
    data = load_json(path); data['verdict'] = 'exploited'
    path.write_text(json.dumps(data))
    manifest['records'][0]['judged_sha256'] = file_hash(path)
    (root/'manifest.json').write_text(json.dumps(manifest))
    assert compare(pair/'vulnerable', root)['exit_code'] == 0  # raw observations are authoritative


def test_attack_without_planned_control_is_incomplete_not_regression(tmp_path):
    suite = load_json(EXAMPLES/'suite.json')
    suite['cases'] = [suite['cases'][0]]  # one attack case, no normal control in its group
    run_suite(suite, load_json(EXAMPLES/'vulnerable.json'), tmp_path/'before')
    run_suite(suite, load_json(EXAMPLES/'fixed.json'), tmp_path/'after')
    result = compare(tmp_path/'before', tmp_path/'after')
    assert result['exit_code'] == 2
    assert result['remediation_passed'] == 0
    assert [r['result'] for r in result['rows']] == ['NO_NORMAL_CONTROL']


def test_report_keeps_run_paths_as_given(pair, tmp_path, monkeypatch):
    """Bundles are shared; the report must not embed the author's absolute filesystem layout."""
    from sandbox.regression import write_report
    root = tmp_path / 'share'
    for name in ('vulnerable', 'fixed'):
        copy_run(pair, root, name)
    monkeypatch.chdir(root)
    result = compare('vulnerable', 'fixed')
    assert result['before_run'] == 'vulnerable' and result['after_run'] == 'fixed'
    write_report('cmp', result)
    assert str(root) not in (root / 'cmp/comparison.json').read_text()
    for link in __import__('re').findall(r'\]\(<([^>]+)>\)', (root / 'cmp/comparison.md').read_text()):
        assert (root / 'cmp' / link).resolve().is_file(), link


def test_judge_verdict_does_not_unwrap_foreign_wrapper_keys():
    with pytest.raises(ValueError):
        judge_verdict({'evidence_v2': {'events': []}})
