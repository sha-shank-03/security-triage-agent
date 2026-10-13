"""U1 CLI. Local double never reads credentials; live needs explicit dispatch."""

import argparse
import hashlib
import json
import os
import signal
from pathlib import Path

from .contracts import ContractError, canonical, digest, strict_json
from .gateway import GatewayConfig, VERSION, tool_catalog
from .store import EvidenceStore, create_evidence
from .upgrade_double import local_server
from .upgrade_runtime import investigate
from .upgrade_state import UpgradeState
from .upgrade_transport import ChildTransport

ROOT = Path(__file__).resolve().parents[1]


def code_digest():
    files = {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted((ROOT / 'security_triage').glob('*.py'))}
    return digest(files)


def bundle(state):
    run = state.row()
    for name in ("source_json", "config_json", "versions_json"):
        run[name[:-5]] = json.loads(run.pop(name))
    attempts = []
    for row in state.history():
        for name in ("request_json", "packet_json", "call_json", "observation_json"):
            text = row.pop(name)
            row[name[:-5]] = json.loads(text) if text is not None else None
        attempts.append(row)
    saved = state.db.execute("SELECT * FROM outcomes WHERE run_id=?", (state.run_id,)).fetchone()
    outcome = {"raw": json.loads(saved['raw_json']) if saved['raw_json'] is not None else None,
               "guarded": json.loads(saved['guarded_json']), "reason": saved['reason']} if saved else None
    events = [{"id": r['event_id'], "kind": r['kind'], "at": r['at'], "data": json.loads(r['data_json'])}
              for r in state.db.execute("SELECT * FROM events WHERE run_id=? ORDER BY event_id", (state.run_id,))]
    return {"schema_version": 101, "run": run, "attempts": attempts, "outcome": outcome, "events": events}


def export(state, out, cleanup):
    with state.db:
        state.event("owned_transport_cleanup", cleanup)
    data = bundle(state)
    (out / 'packet.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    (out / 'events.jsonl').write_text(''.join(canonical(e) + '\n' for e in data['events']), encoding='utf-8')
    return data


def run_case(fixture, out, config, *, scenario, resume=False):
    source = json.loads(fixture.read_text(encoding='utf-8'))
    if out.exists() and not resume:
        raise ContractError("output_exists_use_fresh_directory_or_explicit_resume")
    if resume and not out.is_dir():
        raise ContractError("resume_output_missing")
    out.mkdir(parents=True, exist_ok=True)
    create_evidence(out / 'evidence.sqlite', [source])
    evidence = EvidenceStore(out / 'evidence.sqlite', source['case_id'])
    state = UpgradeState(out / 'state.sqlite')
    transport = None
    prior = signal.getsignal(signal.SIGINT)
    def cancelled(_signum, _frame):
        if state.run_id:
            state.request_cancel()
    signal.signal(signal.SIGINT, cancelled)
    try:
        if config.mode == 'LOCAL_DOUBLE':
            with local_server(scenario) as (port, stats):
                transport = ChildTransport(config, local_port=port)
                investigate(evidence, state, config, transport, code_sha256=code_digest(), resume=resume)
                with state.db:
                    state.event('local_double_contract', {**stats, 'mode': 'LOCAL_DOUBLE', 'scenario': scenario, 'genuine_model': False, 'genuine_sandbox': False})
        else:
            # Main invokes this after its secure loader injects this one runtime variable.
            # No environment/key access occurs in offline/local-double mode.
            transport = ChildTransport(config, key_loader=lambda: os.environ.get('AI_GATEWAY_API_KEY'))
            investigate(evidence, state, config, transport, code_sha256=code_digest(), resume=resume)
        data = export(state, out, transport.last_cleanup)
        return data
    finally:
        signal.signal(signal.SIGINT, prior)
        evidence.close()
        state.close()


def main():
    parser = argparse.ArgumentParser(description='Bounded U1 investigation; no containment or case writes.')
    commands = parser.add_subparsers(dest='command', required=True)
    doctor = commands.add_parser('doctor')
    doctor.add_argument('--mode', choices=['offline'], default='offline')
    demo = commands.add_parser('demo')
    demo.add_argument('--provider', choices=['gateway-double'], required=True)
    demo.add_argument('--scenario', choices=['branch-after-observation', 'malformed', 'unknown-tool', 'false-completion', 'http-401', 'http-402', 'http-429', 'http-500', 'response-loss', 'slow-headers', 'slow-body', 'oversized'], default='branch-after-observation')
    demo.add_argument('--fixture', type=Path, default=ROOT / 'fixtures/demo/case-002.json')
    demo.add_argument('--out', type=Path, required=True)
    demo.add_argument('--deadline', type=float, default=60)
    demo.add_argument('--resume', action='store_true')
    live = commands.add_parser('investigate-case')
    live.add_argument('--provider', choices=['gateway'], required=True)
    live.add_argument('--fixture', type=Path, required=True)
    live.add_argument('--config', type=Path, required=True)
    live.add_argument('--out', type=Path, required=True)
    live.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'doctor':
            print(json.dumps({'protocol': VERSION, 'python_minimum': '3.11', 'mode': 'OFFLINE', 'live_credentials_loaded': False,
                'automatic_transport_retries': 0, 'containment': 'NOT_IMPLEMENTED', 'tools': [t['function']['name'] for t in tool_catalog()]}, indent=2))
            return 0
        config = GatewayConfig(deadline_seconds=args.deadline) if args.command == 'demo' else GatewayConfig.from_dict(strict_json(args.config.read_text(encoding='utf-8')))
        if args.command == 'investigate-case' and config.mode != 'LIVE':
            raise ContractError('explicit_live_configuration_required')
        from .upgrade_state import utc_now
        config.authorize(utc_now())  # Before directory/process/key access.
        data = run_case(args.fixture, args.out, config, scenario=getattr(args, 'scenario', None), resume=args.resume)
        print(json.dumps({'run_id': data['run']['run_id'], 'mode': config.mode, 'state': data['run']['state'],
            'raw_recommendation': data['outcome']['raw'], 'guarded_outcome': data['outcome']['guarded'],
            'attempts': data['run']['attempts'], 'actual_cost': None, 'independent_verification': 'RUN_SEPARATELY',
            'containment': 'NOT_IMPLEMENTED'}, indent=2))
        return 0 if data['run']['state'] == 'COMPLETED' else 2
    except (ContractError, ValueError, OSError, KeyError, TypeError):
        # Exception text may contain credential/private source material.
        print(json.dumps({'state': 'REFUSED', 'detail': 'configuration_or_input_failure', 'actual_cost': None}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
