import sys, os, time
sys.path.insert(0, os.path.abspath("."))
from llm_client import get_llm_client
from agent import SYSTEM_PROMPT, build_user_prompt
from wazuh_listener import normalize_wazuh_alert
from scripts.benchmark_wazuh import BENCHMARK_SCENARIOS

client = get_llm_client()
alert = normalize_wazuh_alert(BENCHMARK_SCENARIOS[0]["payload"])
prompt = build_user_prompt(alert, [], True)

print("Prompt length:", len(prompt))
t0 = time.time()
print("Starting generate...")
res = client.generate(SYSTEM_PROMPT, prompt)
print(f"Done in {time.time()-t0:.2f}s:")
print(res)
