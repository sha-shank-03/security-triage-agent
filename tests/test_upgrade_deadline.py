"""Pure persisted budget, fake-clock deadline and cancellation checks."""

import unittest
from datetime import timedelta
from unittest.mock import patch

from security_triage.contracts import ContractError
from security_triage.gateway import GatewayConfig
from security_triage.upgrade_runtime import versions
from security_triage.upgrade_state import UpgradeState
from security_triage.upgrade_transport import ChildTransport, child_environment, WINDOWS_RUNTIME_VARS
from tests.test_m2_components import MemoryEvidence, NOW


class DeadlinePure(unittest.TestCase):
    def setUp(self):
        self.wall=NOW; self.tick=10
        self.state=UpgradeState(':memory:',clock=lambda:self.wall,monotonic=lambda:self.tick)
        self.config=GatewayConfig(max_attempts=2,deadline_seconds=5)
        self.source=MemoryEvidence().snapshot
        self.state.start(self.source,self.config,versions('a'*64))
    def tearDown(self): self.state.close()

    def test_attempts_and_expiry_not_reset_on_explicit_resume(self):
        expiry=self.state.row()['expires_at']
        seq=self.state.reserve({}); self.state.resolve(seq,'invalid_arguments',correction=True)
        self.tick+=2; self.wall+=timedelta(seconds=2)
        self.state.start(self.source,self.config,versions('a'*64),resume=True)
        self.assertEqual(self.state.row()['expires_at'],expiry)
        self.assertEqual(self.state.row()['attempts'],1)
        self.assertEqual(self.state.row()['corrections'],1)
        self.assertEqual(self.state.deadline,self.tick+3)
        seq=self.state.reserve({}); self.state.resolve(seq,'evidence_read')
        with self.assertRaises(ContractError): self.state.reserve({})

    def test_monotonic_deadline_and_wall_rollback_refuse_dispatch(self):
        self.tick+=5
        with self.assertRaises(ContractError): self.state.reserve({})
        self.tick=10; self.wall-=timedelta(seconds=1)
        with self.assertRaises(ContractError): self.state.reserve({})
        self.assertEqual(self.state.row()['attempts'],0)

    def test_inflight_and_replayed_resolution_refused(self):
        seq=self.state.reserve({})
        with self.assertRaises(ContractError): self.state.reserve({})
        self.state.resolve(seq,'interrupted_unknown_remote_outcome')
        with self.assertRaises(ContractError): self.state.resolve(seq,'evidence_read')

    def test_cancel_blocks_new_reservation(self):
        self.state.request_cancel()
        with self.assertRaises(ContractError): self.state.reserve({})

    def test_deadline_or_cancel_before_transport_never_spawns(self):
        transport=ChildTransport(GatewayConfig(),local_port=1,monotonic=lambda:10)
        with patch('security_triage.upgrade_transport.subprocess.Popen') as spawn:
            with self.assertRaises(ContractError): transport.send({},10,lambda:False)
            with self.assertRaises(ContractError): transport.send({},20,lambda:True)
            spawn.assert_not_called()

    def test_windows_runtime_paths_preserved_without_secrets_or_overrides(self):
        environ={name:'synthetic-runtime-path' for name in WINDOWS_RUNTIME_VARS}
        environ.update(SYSTEMDRIVE='C:',AI_GATEWAY_API_KEY='SENTINEL_PRIVATE_VALUE',
                       PYTHONPATH='untrusted-path',HTTPS_PROXY='untrusted-proxy')
        child=child_environment(environ)
        self.assertEqual(child['SYSTEMDRIVE'],'C:')
        for name in WINDOWS_RUNTIME_VARS: self.assertEqual(child[name],environ[name])
        self.assertEqual(child['PYTHONIOENCODING'],'utf-8')
        self.assertEqual(set(child),set(WINDOWS_RUNTIME_VARS)|{'PYTHONIOENCODING'})
        for secret in ('SENTINEL_PRIVATE_VALUE','untrusted-path','untrusted-proxy'):
            self.assertNotIn(secret,str(child))
        with patch('security_triage.upgrade_transport.os.name','nt'):
            with self.assertRaises(ContractError): child_environment({'SYSTEMROOT':'C:\\Windows'})


if __name__=='__main__': unittest.main()
