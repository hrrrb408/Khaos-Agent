import sys
from pathlib import Path

import pytest

from khaos.coding.intelligence.lsp import LspClient


FAKE_SERVER = """import sys,json
def read():
 h={}
 while True:
  line=sys.stdin.buffer.readline()
  if line in (b'\\r\\n',b'\\n'): break
  k,v=line.decode().split(':',1); h[k.lower()]=v.strip()
 return json.loads(sys.stdin.buffer.read(int(h['content-length'])))
def write(x):
 b=json.dumps(x,separators=(',',':')).encode(); sys.stdout.buffer.write(('Content-Length: %d\\r\\n\\r\\n'%len(b)).encode()+b); sys.stdout.buffer.flush()
while True:
 m=read(); method=m.get('method')
 if method=='initialize': write({'jsonrpc':'2.0','id':m['id'],'result':{'capabilities':{'definitionProvider':True}}})
 elif method=='shutdown': write({'jsonrpc':'2.0','id':m['id'],'result':{}})
 elif method=='exit': break
"""


@pytest.mark.asyncio
async def test_lsp_stdio_lifecycle_and_capabilities(tmp_path: Path):
    server = tmp_path / "server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    client = LspClient((sys.executable, str(server)), timeout=1)
    result = await client.start(tmp_path.as_uri())
    assert result["ok"] is True
    assert result["capabilities"]["definitionProvider"] is True
    await client.close()


@pytest.mark.asyncio
async def test_missing_lsp_server_degrades_without_failing_runtime():
    result = await LspClient(("khaos-no-such-lsp",), timeout=0.1).start("file:///tmp")
    assert result["ok"] is False
    assert result["diagnostic"].code == "server-unavailable"
