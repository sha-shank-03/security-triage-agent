"""Independent U1 packet/source/state verifier. No acting-agent imports."""

import argparse
import hashlib
import json
import math
import re
import sqlite3
from contextlib import closing
from datetime import timedelta
from pathlib import Path

from .independent import check_guarded, expected_read
from .verify import VerificationError, _check, _hash, _time

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {'get_identity_context', 'search_events', 'get_device_context', 'get_network_context',
         'get_travel_context', 'get_telemetry_status', 'finish_investigation'}
NAME = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def unique(pairs):
    result = {}
    for key, value in pairs:
        _check(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(VerificationError('nonfinite JSON')))


def call_from_packet(packet, config):
    _check(packet['choice_count'] == 1 and packet['finish_reason'] == 'tool_calls' and packet['role'] == 'assistant'
           and packet['has_content'] is False and packet['has_refusal'] is False, 'invalid accepted native envelope')
    _check(isinstance(packet['id'], str) and NAME.fullmatch(packet['id']) and packet['model'] == config['model'], 'generation/model identity')
    _check(packet['provider'] is None or (isinstance(packet['provider'], str) and NAME.fullmatch(packet['provider'])
           and (not config['providers'] or packet['provider'] in config['providers'])), 'provider restriction')
    _check(isinstance(packet['tool_calls'], list) and len(packet['tool_calls']) == 1, 'accepted multiple calls')
    call = packet['tool_calls'][0]
    _check(set(call) == {'id', 'type', 'function'} and call['type'] == 'function' and isinstance(call['id'], str)
           and NAME.fullmatch(call['id']), 'invalid native ID/type')
    function = call['function']
    _check(set(function) == {'name', 'arguments'} and function['name'] in TOOLS, 'unknown native tool')
    arguments = parse(function['arguments'])
    _check(isinstance(arguments, dict), 'arguments shape')
    usage = packet['usage']
    if usage is not None:
        _check(all(type(usage.get(k)) is int and usage[k] >= 0 for k in ('prompt_tokens','completion_tokens','total_tokens')), 'usage type')
        _check(usage['total_tokens'] == usage['prompt_tokens'] + usage['completion_tokens']
               and usage['completion_tokens'] <= config['max_tokens'], 'token accounting')
    return {'id': call['id'], 'tool': function['name'], 'arguments': arguments}


def validate_packet(bundle, source):
    """Pure checks against independently supplied input and committed bundle."""
    run, attempts, outcome, events = (bundle[k] for k in ('run', 'attempts', 'outcome', 'events'))
    config = run['config']
    _check(bundle['schema_version'] == 101 and run['source'] == source, 'source substitution')
    _check(config['mode'] in ('LOCAL_DOUBLE', 'LIVE'), 'mode')
    _check(type(config['max_attempts']) is int and 1 <= config['max_attempts'] <= 12
           and type(config['max_corrections']) is int and 0 <= config['max_corrections'] <= 2
           and type(config['deadline_seconds']) in (float,int) and math.isfinite(config['deadline_seconds'])
           and 0 < config['deadline_seconds'] <= 60, 'expanded budget')
    _check(1 <= config['request_bytes'] <= 98304 and 1 <= config['response_bytes'] <= 65536
           and 1 <= config['observation_bytes'] <= 16384 and 1 <= config['max_tokens'] <= 2048, 'expanded byte/token cap')
    _check(_time(run['expires_at']) - _time(run['created_at']) == timedelta(seconds=config['deadline_seconds']), 'reset deadline')
    _check(0 <= run['elapsed'] <= config['deadline_seconds'] + 2.5, 'unbounded active duration')
    _check([a['seq'] for a in attempts] == list(range(1, len(attempts)+1)) and run['attempts'] == len(attempts)
           and len(attempts) <= config['max_attempts'], 'attempt accounting')
    _check(run['reserved'] == sum(a['reservation'] for a in attempts) <= config['allocation_minor_units']
           and all(a['reservation'] == config['attempt_reservation_minor_units'] for a in attempts), 'reservation loss/overflow')
    _check([e['id'] for e in events] == sorted({e['id'] for e in events}), 'event ordering')
    starts = [e for e in events if e['kind'] == 'run_started']
    _check(len(starts) == 1 and starts[0]['data']['automatic_transport_retries'] == 0
           and starts[0]['data']['dataset_sha256'] == _hash(source)
           and starts[0]['data']['config_sha256'] == _hash(config), 'run identity/zero-retry metadata')
    reserved_events = [e['data']['seq'] for e in events if e['kind'] == 'attempt_reserved']
    _check(reserved_events == list(range(1, len(attempts)+1)), 'missing durable reservation')
    correction_count = sum(e['data'].get('correction') is True for e in events if e['kind']=='attempt_resolved')
    _check(correction_count == run['corrections'] <= config['max_corrections'] + 1, 'correction accounting')
    _check(outcome is not None and all(a['reason'] != 'REQUEST_STARTED' for a in attempts), 'false/inflight completion')
    _check(run['versions']['protocol']=='industry-u1-v1', 'protocol attribution')
    seen, pages, cursors, observations, ids = {}, {}, {}, [], set()
    expected_messages = None
    last_raw = None
    for attempt in attempts:
        packet_events=[e for e in events if e['kind']=='raw_packet_recorded' and e['data']['seq']==attempt['seq']]
        if attempt['packet'] is None:
            _check(not packet_events, 'packet event without committed packet')
        else:
            p=attempt['packet']
            _check(len(packet_events)==1 and isinstance(p['wire_sha256'],str) and re.fullmatch('[a-f0-9]{64}',p['wire_sha256']), 'packet receipt/hash')
            metadata=packet_events[0]['data']
            _check(metadata['generation_id']==p['id'] and metadata['model_returned']==p['model']
                   and metadata['provider_returned']==p['provider'] and metadata['usage']==p['usage'], 'generation metadata disagreement')
        request = attempt['request']
        _check(len(canonical(request).encode()) <= config['request_bytes'], 'request size')
        _check(request['model'] == config['model'] and request['stream'] is False and request['tool_choice'] == 'required'
               and request['max_tokens'] == config['max_tokens'], 'wire settings')
        _check({t['function']['name'] for t in request['tools']} == TOOLS and len(request['tools']) == len(TOOLS), 'tool authority')
        terminal = next(t for t in request['tools'] if t['function']['name']=='finish_investigation')
        _check(terminal['function']['parameters']['properties']['proposal']=={'type':'null'}, 'proposal capability')
        _check(request.get('providerOptions') == ({'gateway': {'only': config['providers']}} if config['providers'] else None), 'fallback/provider change')
        if expected_messages is None:
            _check(len(request['messages']) == 2 and request['messages'][0]['role']=='system'
                   and request['messages'][1]['role']=='user', 'initial history')
            _check(_hash(request['messages'][0]['content']) == run['versions']['prompt_sha256'], 'prompt version')
            _check(_hash(request['tools']) == run['versions']['tools_sha256'], 'tools version')
            _check(parse(request['messages'][1]['content']) == {'alert':source['alert'],'window_start':source['window_start'],'cutoff':source['cutoff']}, 'labels/future evidence in initial input')
            expected_messages = request['messages'][:]
        else:
            _check(request['messages'] == expected_messages, 'native continuation changed/omitted')
        if attempt['reason'] in ('evidence_read', 'validated_finish'):
            call = call_from_packet(attempt['packet'], config)
            _check(call == attempt['call'] and call['id'] not in ids, 'call substitution/replay')
        else:
            call = attempt['call']
        if call:
            ids.add(call['id'])
            if call['tool'] == 'finish_investigation':
                last_raw = call['arguments']
        if attempt['observation'] is not None:
            _check(attempt['reason']=='evidence_read' and call['tool']!='finish_investigation', 'observation on rejected call')
            expected = expected_read(source, _hash(source), call['tool'], call['arguments'], seen, pages, cursors)
            _check(attempt['observation'] == expected and len(canonical(expected).encode()) <= config['observation_bytes'], 'observation/source disagreement')
            seen.update({r['id']:r for r in expected['records']})
            observations.append(expected)
            expected_messages.extend([{'role':'assistant','content':None,'tool_calls':[{'id':call['id'],'type':'function','function':{'name':call['tool'],'arguments':canonical(call['arguments'])}}]},
                {'role':'tool','tool_call_id':call['id'],'content':canonical(expected)}])
        elif attempt['reason']!='validated_finish':
            expected_messages.append({'role':'user','content':canonical({'host_rejection':attempt['reason']})})
        if attempt['reason'].startswith('gateway_') or attempt['reason'] in ('transport_response_lost','transport_start_failed','deadline_exhausted','cancel_requested','response_byte_budget'):
            _check(attempt is attempts[-1], 'automatic transport retry after failure')
    _check(outcome['raw'] == last_raw, 'raw recommendation erased/reframed')
    final = outcome['guarded']
    _check(final['proposal'] is None and final['stop_reason'] == outcome['reason'], 'action or altered stop reason')
    check_guarded(final, source, seen, observations)
    _check(run['state'] == ('COMPLETED' if outcome['reason']=='validated_finish' else ('CANCELLED' if outcome['reason']=='cancel_requested' else 'HANDOFF')), 'false state completion')
    if outcome['reason']=='validated_finish':
        _check(not run['cancelled'] and attempts[-1]['reason']=='validated_finish'
               and {k:v for k,v in final.items() if k not in ('execution_status','stop_reason')} == last_raw, 'guard relabeled raw success')
    final_events = [e for e in events if e['kind']=='guarded_outcome_recorded']
    _check(len(final_events)==1 and final_events[0]['data']['guarded']==final, 'committed/event final mismatch')
    _check(final_events[0]['data']['state']==run['state'] and final_events[0]['data']['reason']==outcome['reason']
           and final_events[0]['data']['host_intervention']==(outcome['reason']!='validated_finish'), 'event handoff/intervention mismatch')
    raw_events = [e for e in events if e['kind']=='raw_recommendation_recorded']
    _check(not raw_events or (raw_events[-1]['id'] < final_events[0]['id'] and raw_events[-1]['data']['raw_recommendation']==last_raw), 'raw persistence order')
    _check(last_raw is None or raw_events, 'missing raw event')
    _check(all('actual_cost' not in e['data'] or e['data']['actual_cost'] is None for e in events), 'fabricated actual cost')
    return {'passed':True, 'mode':config['mode'], 'attempts':len(attempts), 'observations':len(observations),
            'raw_guarded_separate':True, 'actual_cost':None, 'external_integration':False, 'containment':'NOT_IMPLEMENTED'}


def load_committed(path):
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True)) as db:
        db.row_factory=sqlite3.Row
        _check(db.execute('PRAGMA user_version').fetchone()[0]==101, 'state schema')
        rows=db.execute('SELECT * FROM runs').fetchall()
        _check(len(rows)==1, 'run cardinality')
        run=dict(rows[0])
        for key in ('source_json','config_json','versions_json'):
            run[key[:-5]]=parse(run.pop(key))
        attempts=[dict(r) for r in db.execute('SELECT * FROM attempts ORDER BY seq')]
        for row in attempts:
            for key in ('request_json','packet_json','call_json','observation_json'):
                text=row.pop(key)
                row[key[:-5]]=parse(text) if text is not None else None
        saved=db.execute('SELECT * FROM outcomes').fetchall()
        _check(len(saved)==1, 'outcome cardinality')
        outcome={'raw':parse(saved[0]['raw_json']) if saved[0]['raw_json'] is not None else None,'guarded':parse(saved[0]['guarded_json']),'reason':saved[0]['reason']}
        events=[{'id':r['event_id'],'kind':r['kind'],'at':r['at'],'data':parse(r['data_json'])} for r in db.execute('SELECT * FROM events ORDER BY event_id')]
        return {'schema_version':101,'run':run,'attempts':attempts,'outcome':outcome,'events':events}


def verify_directory(out, source):
    committed=load_committed(out/'state.sqlite')
    _check(parse((out/'packet.json').read_text(encoding='utf-8'))==committed, 'report/database disagreement')
    _check([parse(line) for line in (out/'events.jsonl').read_text(encoding='utf-8').splitlines()]==committed['events'], 'JSONL/database disagreement')
    with closing(sqlite3.connect((out/'evidence.sqlite').resolve().as_uri()+'?mode=ro',uri=True)) as db:
        row=db.execute('SELECT input_json,digest FROM cases').fetchall()
        _check(len(row)==1 and parse(row[0][0])==source and row[0][1]==_hash(source), 'source DB mutation')
        indexed=[parse(r[0]) for r in db.execute('SELECT record_json FROM records ORDER BY record_id')]
        _check(indexed==sorted(source['records'],key=lambda r:r['id']), 'source index/session mutation')
    code={str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'security_triage').glob('*.py'))}
    _check(committed['run']['versions']['code_sha256']==_hash(code), 'code version changed since run')
    cleanups=[e for e in committed['events'] if e['kind']=='owned_transport_cleanup']
    _check(cleanups and cleanups[-1]['data']['completed'] and not cleanups[-1]['data']['owned_children']
           and cleanups[-1]['data']['cleanup_seconds']<=2.5, 'owned process cleanup')
    return validate_packet(committed, source)


def main():
    parser=argparse.ArgumentParser(description='Independent committed U1 verification; does not run actor or call network.')
    parser.add_argument('--run-dir',type=Path,required=True)
    parser.add_argument('--suite',choices=['provider-contract'],required=True)
    parser.add_argument('--source',type=Path,default=ROOT/'fixtures/demo/case-002.json')
    args=parser.parse_args()
    try:
        result=verify_directory(args.run_dir,parse(args.source.read_text(encoding='utf-8')))
    except (VerificationError,ValueError,OSError,KeyError,TypeError,sqlite3.Error):
        print(json.dumps({'passed':False,'reason':'independent_packet_or_state_verification_failed'}))
        return 1
    print(json.dumps(result,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
