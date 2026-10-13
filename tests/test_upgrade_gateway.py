"""Pure protocol and independent packet checks; no socket/child/actor loop."""

import copy
import json
import unittest

from evaluation.upgrade_verify import validate_packet
from evaluation.verify import VerificationError
from security_triage.contracts import ContractError, canonical
from security_triage.gateway import (GatewayConfig, continuation, decode_packet, exchange,
                                    initial_messages, make_request, project_packet)
from security_triage.policy import claim, validate_final
from security_triage.tools import EvidenceTools
from security_triage.upgrade import bundle
from security_triage.upgrade_double import completion, next_completion
from security_triage.upgrade_runtime import fallback, versions
from security_triage.upgrade_state import UpgradeState
from tests.test_m2_components import MemoryEvidence, NOW


def decoded(tool='get_identity_context', args=None, seq=1):
    config=GatewayConfig()
    return decode_packet(project_packet(canonical(completion(tool,args or {},seq)),config),config)


def committed_packet(*, rejected=False, code_sha256='a'*64):
    evidence=MemoryEvidence()
    config=GatewayConfig()
    state=UpgradeState(':memory:',clock=lambda:NOW,monotonic=lambda:10)
    state.start(evidence.snapshot,config,versions(code_sha256))
    messages=initial_messages(evidence.snapshot)
    tools=EvidenceTools(evidence)
    if not rejected:
        seq=state.reserve(make_request(messages,config))
        packet=project_packet(canonical(completion('search_events',{'kind':'auth'},seq)),config)
        call=decode_packet(packet,config)
        state.record_packet(seq,packet)
        state.record_call(seq,call)
        observation=tools.call(call['tool'],call['arguments'])
        state.resolve(seq,'evidence_read',observation)
        continuation(messages,call,observation)
        login=next(r for r in tools.seen.values() if r['data'].get('outcome')=='success')
        claims=[claim('AUTH_SUCCESS',login)]
    else:
        claims=[]
    raw={'disposition':'INCONCLUSIVE','urgency':'HIGH','claims':claims,'gaps':[],
         'hypotheses':['MISSING_TELEMETRY'],'reason':'insufficient_evidence','proposal':None}
    if rejected:
        raw.update(disposition='BENIGN',urgency='LOW',hypotheses=['APPROVED_NETWORK'],reason='corroborated_benign_context')
    seq=state.reserve(make_request(messages,config))
    packet=project_packet(canonical(completion('finish_investigation',raw,seq)),config)
    state.record_packet(seq,packet)
    state.record_call(seq,decode_packet(packet,config))
    if rejected:
        with unittest.TestCase().assertRaises(ContractError):
            validate_final(raw,tools)
        state.resolve(seq,'invalid_claim_count',correction=True)
        state.finish(raw,fallback(evidence.snapshot,tools,'invalid_claim_count'),'invalid_claim_count')
    else:
        state.finish(raw,validate_final(raw,tools),'validated_finish',seq=seq)
    data=bundle(state)
    state.close()
    return evidence.snapshot,data


class GatewayPure(unittest.TestCase):
    def test_native_call_id_and_observation_continuation(self):
        config=GatewayConfig()
        messages=initial_messages(MemoryEvidence().snapshot)
        call=decoded()
        observation={'records':[]}
        continuation(messages,call,observation)
        request=make_request(messages,config)
        self.assertEqual(request['messages'][-1]['tool_call_id'],call['id'])
        self.assertEqual(request['messages'][-2]['tool_calls'][0]['function']['arguments'],'{}')
        self.assertNotIn('providerOptions',request)
        self.assertEqual(request['tools'][-1]['function']['parameters']['properties']['proposal'],{'type':'null'})

    def test_changing_observed_success_changes_subsequent_device_request(self):
        evidence=MemoryEvidence()
        tools=EvidenceTools(evidence)
        observations=[tools.call('get_identity_context',{}),tools.call('search_events',{'kind':'auth'})]
        first=initial_messages(evidence.snapshot)
        for seq,observation in enumerate(observations,1):
            continuation(first,decoded(observation['tool'],observation['arguments'],seq),observation)
        changed=copy.deepcopy(first)
        last=json.loads(changed[-1]['content'])
        for row in last['records']:
            if row['data']['outcome']=='success': row['data']['device_id']='observed-alternative'
        changed[-1]['content']=canonical(last)
        a=decode_packet(project_packet(canonical(next_completion(make_request(first,GatewayConfig()))),GatewayConfig()),GatewayConfig())
        b=decode_packet(project_packet(canonical(next_completion(make_request(changed,GatewayConfig()))),GatewayConfig()),GatewayConfig())
        self.assertEqual(a['tool'],b['tool'])
        self.assertEqual(a['tool'],'get_device_context')
        self.assertNotEqual(a['arguments'],b['arguments'])
        self.assertEqual(b['arguments'],{'device_id':'observed-alternative'})

    def test_malformed_duplicate_multiple_unknown_and_refusal_rejected(self):
        config=GatewayConfig()
        for raw in ('{','{"id":1,"id":2}','x'*65537):
            with self.subTest(raw=raw[:20]),self.assertRaises(ContractError): project_packet(raw,config)
        mutations=[lambda p:p['choices'][0]['message'].update(tool_calls=[]),
                   lambda p:p['choices'][0]['message']['tool_calls'].append(copy.deepcopy(p['choices'][0]['message']['tool_calls'][0])),
                   lambda p:p['choices'][0]['message'].update(refusal='private refusal'),
                   lambda p:p['choices'][0]['message'].update(content='untrusted completion'),
                   lambda p:p['choices'][0]['message']['tool_calls'][0]['function'].update(name='shell')]
        for mutate in mutations:
            p=completion('get_identity_context',{})
            mutate(p)
            with self.assertRaises(ContractError): decode_packet(project_packet(canonical(p),config),config)

    def test_missing_usage_unknown_and_invalid_usage_fail_closed(self):
        config=GatewayConfig()
        p=completion('get_identity_context',{})
        self.assertIsNone(project_packet(canonical(p),config)['usage'])
        for usage in ({'prompt_tokens':1,'completion_tokens':1,'total_tokens':False},
                      {'prompt_tokens':1,'completion_tokens':2049,'total_tokens':2050},
                      {'prompt_tokens':1,'completion_tokens':1,'total_tokens':3}):
            p['usage']=usage
            with self.assertRaises(ContractError): decode_packet(project_packet(canonical(p),config),config)

    def test_http_denials_rate_limit_and_server_failure_send_once(self):
        class Fake:
            def __init__(self,status): self.calls=0; self.status=status
            def send(self,*_): self.calls+=1; return self.status,'private-error-not-logged'
        for status in (401,402,403,429,500):
            transport=Fake(status)
            with self.assertRaises(ContractError): exchange(transport,{},GatewayConfig(),20,lambda:False)
            self.assertEqual(transport.calls,1)

    def test_model_identity_call_shape_and_history_bound(self):
        p=completion('get_identity_context',{})
        p['model']='unapproved/model'
        with self.assertRaises(ContractError): decode_packet(project_packet(canonical(p),GatewayConfig()),GatewayConfig())
        with self.assertRaises(ContractError): make_request([{'role':'user','content':'x'*98304}],GatewayConfig())
        self.assertNotIn('reasoning',project_packet(canonical({**completion('get_identity_context',{}),'reasoning':'private'}),GatewayConfig()))

    def test_independent_committed_packet_and_corruptions(self):
        source,data=committed_packet()
        self.assertTrue(validate_packet(data,source)['passed'])
        mutations=[lambda b:b['attempts'][0]['observation']['records'][0].update(version=99),
                   lambda b:b['outcome']['guarded']['claims'][0].update(value=False),
                   lambda b:b['run'].update(attempts=0),
                   lambda b:b['attempts'][1]['request']['messages'][-1].update(tool_call_id='forged'),
                   lambda b:b['outcome'].update(raw=None),
                   lambda b:b['events'][-1]['data'].update(actual_cost=0),
                   lambda b:b['attempts'][0]['packet'].update(id='forged-generation')]
        for mutate in mutations:
            corrupted=copy.deepcopy(data); mutate(corrupted)
            with self.assertRaises(VerificationError): validate_packet(corrupted,source)

    def test_rejected_raw_recommendation_persists_before_guarded_fallback(self):
        source,data=committed_packet(rejected=True)
        self.assertTrue(validate_packet(data,source)['passed'])
        self.assertNotEqual(data['outcome']['raw'],data['outcome']['guarded'])
        self.assertEqual(data['outcome']['raw']['disposition'],'BENIGN')
        self.assertEqual(data['outcome']['guarded']['disposition'],'INCONCLUSIVE')
        kinds=[e['kind'] for e in data['events']]
        self.assertLess(kinds.index('raw_recommendation_recorded'),kinds.index('guarded_outcome_recorded'))


if __name__=='__main__': unittest.main()
