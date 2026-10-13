"""HEAVY: real loopback sockets/owned children. Requires a named main lease."""

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from evaluation.upgrade_verify import verify_directory
from security_triage.contracts import ContractError
from security_triage.gateway import GatewayConfig, GatewayFailure, exchange, initial_messages, make_request
from security_triage.upgrade import ROOT, run_case
from security_triage.upgrade_double import local_server
from security_triage.upgrade_transport import ChildTransport


class TransportIntegration(unittest.TestCase):
    def request(self, config):
        source=json.loads((ROOT/'fixtures/demo/case-002.json').read_text(encoding='utf-8'))
        return make_request(initial_messages(source),config)

    def test_http_failures_have_one_request_and_no_authorization(self):
        config=GatewayConfig()
        for status in (401,402,403,429,500):
            with local_server('http-'+str(status)) as (port,stats):
                transport=ChildTransport(config,local_port=port)
                with self.assertRaises(GatewayFailure) as raised:
                    exchange(transport,self.request(config),config,time.monotonic()+5,lambda:False)
                self.assertEqual(raised.exception.status,status)
                self.assertEqual(stats['requests'],1)
                self.assertFalse(stats['authorization_present'])
                self.assertTrue(transport.last_cleanup['completed'])
                self.assertEqual(transport.last_cleanup['owned_children'],[])

    def test_header_and_body_stalls_obey_total_deadline_and_cleanup(self):
        config=GatewayConfig(deadline_seconds=.4)
        for scenario in ('slow-headers','slow-body'):
            with local_server(scenario) as (port,stats):
                transport=ChildTransport(config,local_port=port)
                started=time.monotonic()
                with self.assertRaises(GatewayFailure) as raised:
                    exchange(transport,self.request(config),config,started+.4,lambda:False)
                self.assertEqual(raised.exception.code,'deadline_exhausted')
                self.assertLessEqual(time.monotonic()-started,2.5)
                self.assertTrue(transport.last_cleanup['completed'])
                self.assertEqual(transport.last_cleanup['owned_children'],[])
                self.assertLessEqual(stats['requests'],1)

    def test_cancel_and_ambiguous_loss_do_not_replay(self):
        config=GatewayConfig()
        with local_server('slow-body') as (port,stats):
            cancel=threading.Event()
            timer=threading.Timer(.25,cancel.set)
            timer.start()
            transport=ChildTransport(config,local_port=port)
            try:
                with self.assertRaises(GatewayFailure) as raised:
                    exchange(transport,self.request(config),config,time.monotonic()+5,cancel.is_set)
                self.assertEqual(raised.exception.code,'cancel_requested')
                self.assertTrue(transport.last_cleanup['completed'])
                self.assertEqual(transport.last_cleanup['owned_children'],[])
            finally:
                timer.cancel(); timer.join(timeout=1)
        for scenario in ('response-loss','oversized'):
            with local_server(scenario) as (port,stats):
                transport=ChildTransport(config,local_port=port)
                with self.assertRaises(GatewayFailure):
                    exchange(transport,self.request(config),config,time.monotonic()+5,lambda:False)
                self.assertEqual(stats['requests'],1)
                self.assertEqual(transport.last_cleanup['owned_children'],[])

    def test_native_journey_and_false_completion_independently_checked(self):
        fixture=ROOT/'fixtures/demo/case-002.json'
        source=json.loads(fixture.read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as directory:
            for scenario in ('branch-after-observation','false-completion','unknown-tool','malformed'):
                out=Path(directory)/scenario
                result=run_case(fixture,out,GatewayConfig(),scenario=scenario)
                verified=verify_directory(out,source)
                self.assertTrue(verified['passed'])
                self.assertEqual(result['run']['config']['mode'],'LOCAL_DOUBLE')
                self.assertEqual(result['outcome']['guarded']['execution_status'],'NOT_IMPLEMENTED')
                self.assertEqual(result['run']['state'],'COMPLETED' if scenario=='branch-after-observation' else 'HANDOFF')
                if scenario=='branch-after-observation':
                    self.assertEqual(result['outcome']['raw']['disposition'],'ESCALATE')
                    self.assertGreaterEqual(verified['observations'],2)
                if scenario=='false-completion':
                    self.assertEqual(result['outcome']['raw']['disposition'],'BENIGN')
                    self.assertEqual(result['outcome']['guarded']['disposition'],'INCONCLUSIVE')


if __name__=='__main__': unittest.main()
