import json
from pathlib import Path

from wiguard.services.artifacts import generate_artifacts
from wiguard.services.intelligence import (
    build_analyst_signoff,
    build_evidence_quality_matrix,
    build_report,
    build_topology_dot,
)
from wiguard.services.reporting import REPORT_TYPES, custom_report_html_bytes, report_html_bytes


def _state():
    return json.loads(Path('data/state.json').read_text(encoding='utf-8'))


def test_quality_report_type_and_payload_shape():
    state = _state()
    assert 'quality' in REPORT_TYPES
    payload = build_report(state, 'quality')
    assert payload['report_type'] == 'quality'
    assert 'evidence_quality_matrix' in payload
    assert 'analyst_signoff' in payload
    assert isinstance(payload['evidence_quality_matrix']['rows'], list)
    assert 'can_publish_technical' in payload['analyst_signoff']


def test_quality_matrix_and_signoff_are_truth_first():
    state = _state()
    matrix = build_evidence_quality_matrix(state)
    signoff = build_analyst_signoff(state)
    assert 0 <= matrix['score'] <= 100
    assert matrix['grade']
    assert isinstance(signoff['allowed_claims'], list)
    assert isinstance(signoff['forbidden_claims'], list)
    assert 'can_claim_full_fidelity' in signoff


def test_quality_artifacts_and_topology_dot(tmp_path):
    state = _state()
    files, manifest = generate_artifacts(state, tmp_path)
    assert 'evidence_quality_matrix.json' in files
    assert 'analyst_signoff.json' in files
    assert 'topology_graph.dot' in files
    assert Path(files['topology_graph.dot']).read_text(encoding='utf-8').startswith('digraph WiGuardTopology')
    assert manifest['artifact_count'] >= 1


def test_quality_report_exports_render():
    state = _state()
    html = report_html_bytes(state, 'quality').getvalue().decode('utf-8')
    custom = custom_report_html_bytes(state, ['quality', 'signoff']).getvalue().decode('utf-8')
    assert 'Evidence Quality Matrix' in html
    assert 'Analyst Sign-off' in html
    assert 'Evidence Quality Matrix' in custom
    assert build_topology_dot(state).startswith('digraph WiGuardTopology')
