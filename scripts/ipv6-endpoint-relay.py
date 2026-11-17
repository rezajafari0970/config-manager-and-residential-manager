#!/usr/bin/env python3
"""Scoped byte-transparent IPv6 endpoint relay; no global forwarding changes.

Only the sandbox peer can connect, and destinations are numeric public IPv6
IP:port pairs selected before launching untrusted configurations. TLS, REALITY,
QUIC and WireGuard bytes are never decoded or changed here.
"""
import asyncio, contextlib, ipaddress, json, os, pathlib, resource, signal, socket, sys

def validate(request):
    gateway=ipaddress.IPv6Address(request['gateway']);peer=ipaddress.IPv6Address(request['peer'])
    if gateway not in ipaddress.IPv6Network('fd7c:636d:7200::/48') or int(peer)!=int(gateway)+1:raise ValueError('invalid peer')
    pairs=[]
    for ip,port in request['pairs']:
        address=ipaddress.IPv6Address(ip)
        if not address.is_global or address.is_multicast or address.is_reserved or address.ipv4_mapped or not isinstance(port,int) or not 1<=port<=65535:raise ValueError('invalid destination')
        pairs.append((str(address),port))
    if not 1<=len(pairs)<=128 or len(set(pairs))!=len(pairs):raise ValueError('invalid endpoint count')
    return str(gateway),str(peer),pairs

class RemoteUDP(asyncio.DatagramProtocol):
    def __init__(self,owner,key):self.owner,self.key=owner,key
    def connection_made(self,t):self.transport=t
    def datagram_received(self,data,addr):
        if len(data)<=65507:self.owner.transport.sendto(data,self.key)
    def error_received(self,e):pass

class LocalUDP(asyncio.DatagramProtocol):
    def __init__(self,peer,target):self.peer,self.target=peer,target;self.sessions={};self.pending=set();self.tasks=set()
    def connection_made(self,t):self.transport=t
    def datagram_received(self,data,addr):
        if addr[0]!=self.peer or len(data)>65507:return
        if addr in self.sessions:self.sessions[addr][0].sendto(data);return
        if addr in self.pending or len(self.sessions)+len(self.pending)>=8:return
        self.pending.add(addr);task=asyncio.create_task(self.open(addr,data));self.tasks.add(task);task.add_done_callback(self.tasks.discard)
    async def open(self,addr,data):
        transport=None
        try:
            transport,_=await asyncio.wait_for(asyncio.get_running_loop().create_datagram_endpoint(lambda:RemoteUDP(self,addr),remote_addr=self.target,family=socket.AF_INET6),5)
            self.sessions[addr]=(transport,asyncio.get_running_loop().call_later(240,self.close,addr));transport.sendto(data)
        except (OSError,TimeoutError):
            if transport:transport.close()
        finally:self.pending.discard(addr)
    def close(self,addr):
        value=self.sessions.pop(addr,None)
        if value:value[0].close();value[1].cancel()
    def connection_lost(self,e):
        for task in self.tasks:task.cancel()
        for addr in list(self.sessions):self.close(addr)

async def serve(request):
    gateway,peer,pairs=validate(request);servers=[];datagrams=[];mappings=[];active=0
    async def client(reader,writer,target):
        nonlocal active
        remote=None
        if writer.get_extra_info('peername')[0]!=peer or active>=64:writer.close();return
        active+=1
        async def pump(src,dst):
            while True:
                chunk=await asyncio.wait_for(src.read(65536),40)
                if not chunk:break
                dst.write(chunk);await asyncio.wait_for(dst.drain(),40)
            with contextlib.suppress(OSError,AttributeError):dst.write_eof()
        try:
            async with asyncio.timeout(240):
                rr,remote=await asyncio.wait_for(asyncio.open_connection(*target,family=socket.AF_INET6),8)
                await asyncio.gather(pump(reader,remote),pump(rr,writer))
        except (OSError,TimeoutError):pass
        finally:
            active-=1;writer.close()
            if remote:remote.close()
    for target in pairs:
        server=await asyncio.start_server(lambda r,w,t=target:client(r,w,t),gateway,0,family=socket.AF_INET6,limit=65536,backlog=32)
        port=server.sockets[0].getsockname()[1]
        transport,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda t=target:LocalUDP(peer,t),local_addr=(gateway,port),family=socket.AF_INET6)
        servers.append(server);datagrams.append(transport);mappings.append([*target,port])
    print(json.dumps(mappings),flush=True)
    await asyncio.Event().wait()

if __name__=='__main__':
    request=json.loads(sys.stdin.buffer.readline(32768));validate(request)
    parent=os.getppid()
    if parent==1:raise SystemExit('parent unavailable')
    resource.setrlimit(resource.RLIMIT_NOFILE,(512,512));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if os.geteuid()==0:os.setgroups([]);os.setgid(65534);os.setuid(65534)
    async def main():
        async def watch():
            while os.getppid()==parent:await asyncio.sleep(.5)
            os.kill(os.getpid(),signal.SIGTERM)
        asyncio.create_task(watch());await serve(request)
    asyncio.run(main())
