"""Pure portable dispatch/counter tests; no ledger or credential access."""

import unittest
from dataclasses import replace
from datetime import timedelta

from security_triage.contracts import ContractError
from security_triage.gateway import GatewayConfig
from security_triage.upgrade_runtime import versions
from security_triage.upgrade_state import UpgradeState, iso
from tests.test_m2_components import MemoryEvidence, NOW


def live_config():
    return GatewayConfig(mode='LIVE',model='example/explicit-model',providers=('example-provider',),allocation_minor_units=7,
        attempt_reservation_minor_units=4,dispatch={'lease_id':'synthetic-test-lease','expires_at':iso(NOW+timedelta(seconds=30)),
        'approved':True,'pricing_verified':True,'billable_cap_verified':True,'catalog_sha256':'a'*64,'currency':'INR'})


class SpendPure(unittest.TestCase):
    def test_live_missing_unknown_or_expired_authority_refused(self):
        with self.assertRaises(ContractError): GatewayConfig(mode='LIVE',model='example/model').authorize(NOW)
        for key in ('approved','pricing_verified','billable_cap_verified'):
            config=live_config(); d=dict(config.dispatch); d[key]=False
            with self.assertRaises(ContractError): replace(config,dispatch=d).authorize(NOW)
        with self.assertRaises(ContractError): live_config().authorize(NOW+timedelta(seconds=31))

    def test_unknown_cost_reservation_survives_error_and_blocks_overallocation(self):
        state=UpgradeState(':memory:',clock=lambda:NOW,monotonic=lambda:10)
        try:
            state.start(MemoryEvidence().snapshot,live_config(),versions('a'*64))
            seq=state.reserve({}); state.resolve(seq,'transport_response_lost')
            self.assertEqual(state.row()['reserved'],4)
            with self.assertRaises(ContractError): state.reserve({})
            self.assertEqual(state.row()['attempts'],1)
        finally: state.close()

    def test_local_config_cannot_accept_live_dispatch_or_credentials(self):
        with self.assertRaises(ContractError): GatewayConfig(dispatch=live_config().dispatch)
        with self.assertRaises(ContractError): GatewayConfig.from_dict({'api_key':'forbidden'})
        with self.assertRaises(ContractError): GatewayConfig(model='gpt-6.1-sol')
        self.assertEqual(GatewayConfig().allocation_minor_units,0)


if __name__=='__main__': unittest.main()
