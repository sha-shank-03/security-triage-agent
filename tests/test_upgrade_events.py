"""Pure negative controls for redaction and raw packet projection."""

import json
import unittest

from security_triage.contracts import canonical
from security_triage.gateway import GatewayConfig, project_packet
from security_triage.upgrade_double import completion
from security_triage.upgrade_events import redact


class EventsPure(unittest.TestCase):
    def test_secret_keys_patterns_nested_argument_strings_and_sentinel(self):
        value={'authorization':'opaque','reasoning':'private','nested':['Bearer private-value','sk-proj-abcdef',
               {'arguments':json.dumps({'api_key':'opaque-value','item':'SENTINEL_PRIVATE_VALUE'})}]}
        serialized=canonical(redact(value,('SENTINEL_PRIVATE_VALUE',)))
        for secret in ('private-value','sk-proj-abcdef','opaque-value','SENTINEL_PRIVATE_VALUE','private'):
            self.assertNotIn(secret,serialized)

    def test_provider_content_reasoning_error_and_extra_usage_text_not_projected(self):
        raw=completion('get_identity_context',{})
        raw.update(error={'secret':'private-error'},reasoning='private-thought')
        raw['choices'][0]['message'].update(content='private-free-text',reasoning_content='private-chain')
        raw['usage']={'prompt_tokens':1,'completion_tokens':1,'total_tokens':2,'extra':'private-usage'}
        projected=canonical(project_packet(canonical(raw),GatewayConfig()))
        for secret in ('private-error','private-thought','private-free-text','private-chain','private-usage'):
            self.assertNotIn(secret,projected)


if __name__=='__main__': unittest.main()
