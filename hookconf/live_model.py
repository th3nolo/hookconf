"""Fixed-origin real inference relay. No tool-call or response synthesis."""
import hashlib
import http.server
import json
from pathlib import Path
import threading
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener
from urllib.error import HTTPError


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):
        raise HTTPError(request.full_url,code,'redirect refused',headers,fp)


class LiveModel:
    def __init__(self, key, model, *, max_output_tokens=4096, max_requests=64, log_path=None):
        self.key, self.model = key, model
        self.max_output_tokens, self.max_requests = max_output_tokens, max_requests
        self.records=[]
        self.lock=threading.Lock()
        self.log_path=Path(log_path) if log_path is not None else None

    def log(self,row):
        if self.log_path is not None:
            with self.lock, self.log_path.open('a',encoding='utf-8') as stream:
                stream.write(json.dumps(row)+'\n')

    def start(self):
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                if self.path != '/v1/responses':
                    self.send_error(404);return
                with owner.lock:
                    if len(owner.records) >= owner.max_requests:
                        self.send_error(429);return
                    row={'request':len(owner.records)+1}
                    owner.records.append(row)
                try:
                    row.update(content_encoding=self.headers.get('Content-Encoding'),transfer_encoding=self.headers.get('Transfer-Encoding'),
                               content_length=self.headers.get('Content-Length'))
                    owner.log(dict(row,stage='received'))
                    size=int(self.headers.get('Content-Length','0'))
                    if not 0 < size <= 2*1024*1024: raise ValueError('request limit')
                    body=json.loads(self.rfile.read(size))
                    if body.get('model') != owner.model: raise ValueError('model mismatch')
                    body['max_output_tokens']=owner.max_output_tokens
                    payload=json.dumps(body).encode()
                    row.update(model=body['model'],input_sha256=hashlib.sha256(payload).hexdigest(),
                        input_bytes=len(payload),max_output_tokens=owner.max_output_tokens,
                        tools=[t.get('name',t.get('type')) for t in body.get('tools',[])])
                    owner.log(dict(row,stage='request'))
                    request=Request('https://openrouter.ai/api/v1/responses',data=payload,
                        headers={'Authorization':'Bearer '+owner.key,'Content-Type':'application/json','Accept':'text/event-stream'})
                    digest=hashlib.sha256(); total=0; events=bytearray()
                    with build_opener(ProxyHandler({}),NoRedirect()).open(request,timeout=180) as response:
                        row['status']=response.status
                        owner.log(dict(row,stage='headers'))
                        self.send_response(response.status)
                        self.send_header('Content-Type',response.headers.get('Content-Type','text/event-stream'))
                        self.send_header('Connection','close');self.end_headers()
                        while chunk:=response.read1(8192):
                            digest.update(chunk);total+=len(chunk)
                            if total>16*1024*1024:raise ValueError('response limit')
                            self.wfile.write(chunk);self.wfile.flush()
                            events.extend(chunk)
                    row.update(response_sha256=digest.hexdigest(),response_bytes=total,response_forwarded_unchanged=True)
                    for line in events.splitlines():
                        if line.startswith(b'data: {'):
                            event=json.loads(line[6:])
                            if event.get('type') == 'response.completed':
                                final=event.get('response',{})
                                row.update(served_model=final.get('model'),usage=final.get('usage'))
                except Exception as exc:
                    row.update(error_type=type(exc).__name__,status=getattr(exc,'code',row.get('status')))
                    # Never echo upstream errors, authorization headers or key-management URLs.
                    if not row.get('response_bytes'):
                        try: self.send_error(getattr(exc,'code',502),'live inference unavailable')
                        except OSError: pass
                finally:
                    owner.log(dict(row,stage='finished'))
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url=f'http://127.0.0.1:{self.server.server_port}'
        return self

    def stop(self):
        self.server.shutdown();self.server.server_close();self.thread.join(2)
