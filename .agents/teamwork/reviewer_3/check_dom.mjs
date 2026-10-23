import { spawn } from 'child_process';

async function main() {
  const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const chrome = spawn(chromePath, [
    "--headless=new",
    "--remote-debugging-port=9555",
    "--user-data-dir=d:\\soc-agent\\.chrome_temp_check",
    "--window-size=1920,1080",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check"
  ]);

  let wsUrl = null;
  for (let i = 0; i < 20; i++) {
    await new Promise(r => setTimeout(r, 500));
    try {
      const res = await fetch("http://127.0.0.1:9555/json/list");
      const list = await res.json();
      if (list && list[0] && list[0].webSocketDebuggerUrl) {
        wsUrl = list[0].webSocketDebuggerUrl;
        break;
      }
    } catch {}
  }

  if (!wsUrl) {
    console.error("Failed to connect to Chrome CDP on 9555");
    chrome.kill();
    process.exit(1);
  }

  const ws = new WebSocket(wsUrl);
  await new Promise((resolve) => ws.onopen = resolve);

  let msgId = 1;
  function send(method, params = {}) {
    const id = msgId++;
    return new Promise((resolve) => {
      const handler = (evt) => {
        const data = JSON.parse(evt.data);
        if (data.id === id) {
          ws.removeEventListener('message', handler);
          resolve(data.result);
        }
      };
      ws.addEventListener('message', handler);
      ws.send(JSON.stringify({ id, method, params }));
    });
  }

  await send("Page.enable");
  await send("Page.navigate", { url: "http://localhost:8501" });

  // Wait until tabs are present
  for (let i = 0; i < 25; i++) {
    await new Promise(r => setTimeout(r, 1000));
    const chk = await send("Runtime.evaluate", {
      expression: "document.querySelectorAll('[data-baseweb=\"tab\"]').length",
      returnByValue: true
    });
    const count = chk?.result?.value || 0;
    if (count > 0) {
      console.log(`Tabs found (${count}) in ${i+1}s`);
      break;
    }
  }

  const snap = await send("Page.captureScreenshot", { format: "png" });
  if (snap && snap.data) {
    import('fs').then(fs => fs.writeFileSync(".agents/teamwork/reviewer_3/check_dom_snap.png", Buffer.from(snap.data, "base64")));
  }

  const doc = await send("Runtime.evaluate", {
    expression: "document.body.innerText",
    returnByValue: true
  });
  console.log("BODY TEXT:", doc.result.value);
  ws.close();
  chrome.kill();
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
