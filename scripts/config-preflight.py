"""Static egress checks for exact final configs. Does not certify health."""
import copy,ipaddress,json
VERSION='exact-runtime-preflight.v2'
def fail(code):raise ValueError(code)
PROXY_PROTOCOLS = {'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard'}
ROUTING_PROTOCOLS = {'freedom', 'direct', 'blackhole', 'block', 'dns', 'loopback', 'selector', 'urltest'}
DISABLED_PROTOCOLS = {'hy', 'hy1', 'hy2', 'hysteria', 'hysteria1', 'hysteria2'}

def parse_runtime_config(data):
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail('protocol_disabled')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique_fields)

def require_enabled_config(config):
    """Enforce the upstream policy on exact runtime JSON before a core starts."""
    routes = {'outbound', 'outbounds', 'outbounddetour', 'outbounddetours', 'endpoints', 'proxies'}
    listeners = {'inbound', 'inbounds', 'inbounddetour', 'inbounddetours'}
    local_types = {'socks', 'socks5', 'http', 'mixed', 'tun', 'dokodemo-door', 'tunnel', 'redirect', 'tproxy', 'direct'}
    stream_keys = {'streamsettings', 'transport', 'downloadsettings'}
    structure = routes | listeners
    selectors = structure | stream_keys | {'type', 'protocol', 'network', 'net'}
    local_types |= PROXY_PROTOCOLS

    def walk(value, section):
        if isinstance(value, list):
            found = False
            for child in value:
                if walk(child, section):
                    found = True
            return found
        if not isinstance(value, dict):
            if section in ('outbound', 'inbound'):
                fail('protocol_disabled')
            return False
        found = declared = False
        seen = set()
        for field, child in value.items():
            key = field.strip().casefold()
            if section != 'ignored' and key in selectors:
                if key in seen:
                    fail('protocol_disabled')
                seen.add(key)
            selector = child.strip().casefold() if isinstance(child, str) else ''
            if section in ('outbound', 'inbound') and key in ('protocol', 'type'):
                if declared:
                    fail('protocol_disabled')
                declared = True
                if section == 'outbound':
                    if selector in PROXY_PROTOCOLS:
                        found = True
                    elif selector not in ROUTING_PROTOCOLS:
                        fail('protocol_disabled')
                elif selector not in local_types:
                    fail('protocol_disabled')
            if section in ('root', 'inbound', 'outbound', 'stream'):
                if (key in ('network', 'net', 'transport') or section == 'stream' and key in ('type', 'method')) and selector in DISABLED_PROTOCOLS:
                    fail('protocol_disabled')
                if key in ('hysteriasettings', 'hysteria1settings', 'hysteria2settings', 'hy2settings') and child:
                    fail('protocol_disabled')
            if isinstance(child, (list, dict)) or section == 'root' and key in structure:
                next_section = 'ignored'
                if section == 'root' and key in routes:
                    next_section = 'outbound'
                elif section == 'root' and key in listeners:
                    next_section = 'inbound'
                elif key in stream_keys:
                    next_section = 'stream'
                if walk(child, next_section):
                    found = True
        if section in ('outbound', 'inbound') and not declared:
            fail('protocol_disabled')
        return found
    if not isinstance(config, dict) or not walk(config, 'root'):
        fail('protocol_disabled')

def relay_tcp_mask(value,network):
    # Same narrow driver as internal/compat: only a TCP Fragment wrapper;
    # nothing here may add another dial destination or UDP camouflage.
    if network not in ('','tcp','raw','ws','websocket','httpupgrade','grpc','xhttp','splithttp'):return False
    if not isinstance(value,dict) or set(value)-{'tcp'}:return False
    if not value:return True
    masks=value.get('tcp')
    return isinstance(masks,list) and all(isinstance(m,dict) and m.get('type')=='fragment' and not set(m)-{'type','settings'} for m in masks)
def relay_endpoints(c):
    obs=c.get('outbounds',[]);ins=c.get('inbounds',[])
    bytag={x.get('tag'):x for x in obs};rules=c.get('routing',{}).get('rules',[])
    relays={};legs=set();routes=set()
    for ob in obs:
        if ob.get('protocol')!='vless':continue
        s=ob.get('settings',{})
        node=s if 'address' in s else (s.get('vnext') or [{}])[0]
        if node.get('address')!='127.0.0.1':continue
        stream=ob.get('streamSettings',{})
        if stream.get('security','none') not in ('','none') or stream.get('method',stream.get('network','tcp')) not in ('','tcp','raw'):fail('relay_family_not_qualified')
        users=[s] if node is s else node.get('users',[])
        if len(users)!=1 or users[0].get('encryption','none') not in ('','none') or users[0].get('flow'):fail('relay_family_not_qualified')
        if stream.get('sockopt') or ob.get('proxySettings') or ob.get('sendThrough'):fail('relay_local_carrier_invalid')
        if any(k in stream for k in ('finalmask','address','port')):fail('relay_family_not_qualified')
        found=[x for x in ins if x.get('listen')=='127.0.0.1' and x.get('port')==node.get('port') and x.get('protocol') in ('dokodemo-door','tunnel')]
        if len(found)!=1:fail('relay_listener_missing')
        inbound=found[0];tag=inbound.get('tag');cfg=inbound.get('settings',{})
        if set(inbound)-{'tag','listen','port','protocol','settings'} or set(cfg)-{'address','port','network','followRedirect'} or cfg.get('network')!='tcp' or cfg.get('followRedirect') is not False:fail('relay_listener_unbounded')
        host,port=cfg.get('address'),cfg.get('port')
        if not isinstance(host,str) or not isinstance(port,int) or not 1<=port<=65535:fail('relay_destination_invalid')
        try:ipaddress.ip_address(host);key,value='ip',host
        except ValueError:key,value='domain','full:'+host
        scoped=[]
        for i,r in enumerate(rules):
            if tag in r.get('inboundTag',[]):scoped.append((i,r))
            elif not r.get('inboundTag') and len(scoped)<2:fail('relay_route_shadowed')
            if len(scoped)==2:break
        if len(scoped)!=2:fail('relay_deny_missing')
        (ai,a),(di,d)=scoped;leg=a.get('outboundTag');block=d.get('outboundTag')
        if a!={'type':'field','inboundTag':[tag],'network':'tcp',key:[value],'port':str(port),'outboundTag':leg}:fail('relay_route_unbounded')
        if d!={'type':'field','inboundTag':[tag],'network':'tcp,udp','outboundTag':block} or bytag.get(block,{}).get('protocol')!='blackhole':fail('relay_deny_missing')
        carrier=bytag.get(leg,{})
        if carrier.get('protocol')!='freedom' or carrier.get('settings')!={} or set(carrier)-{'tag','protocol','settings','streamSettings','sendThrough'} or set(carrier.get('streamSettings',{}))-{'sockopt'}:fail('relay_carrier_invalid')
        ident=(node['address'],node['port'])
        if ident in relays:fail('relay_listener_shared')
        relays[ident]=(host,port);legs.add(leg);routes.update((ai,di))
    # Any direct route outside the fixed carrier is disallowed in a proxy-health
    # certificate; unused original helpers remain intact.
    for i,r in enumerate(rules):
        if bytag.get(r.get('outboundTag'),{}).get('protocol')=='freedom' and i not in routes:fail('direct_route_not_qualified')
    if obs and obs[0].get('protocol')=='freedom':fail('direct_default_not_qualified')
    for ob in obs:
        for ref in (ob.get('proxySettings',{}).get('tag'),ob.get('streamSettings',{}).get('sockopt',{}).get('dialerProxy')):
            if ref in legs:fail('relay_carrier_shared')
    return relays
def runtime_config(config,resolved,socks_port=10808):
    relay_endpoints(logical_for_inspection(config))
    listeners=set()
    for x in config.get('inbounds',[]):
        if x.get('listen')!='127.0.0.1':fail('nonloopback_listener_not_qualified')
        port=x.get('port')
        if not isinstance(port,int) or port in listeners:fail('listener_port_conflict')
        listeners.add(port)
    socks=[x for x in config.get('inbounds',[]) if x.get('protocol')=='socks' and x.get('port')==socks_port]
    if len(socks)!=1 or socks[0].get('settings',{}).get('auth','noauth')!='noauth':fail('probe_socks_contract_missing')
    return copy.deepcopy(config)

def logical_for_inspection(config):
    """Inspect real destinations without modifying any bytes used by the core."""
    c=copy.deepcopy(config);obs=c.get('outbounds',[])
    bytag={}
    for ob in obs:
        tag=ob.get('tag')
        if tag and tag in bytag:fail('duplicate_outbound_tag')
        if tag:bytag[tag]=ob
    remove=set()
    for ob in obs:
        if ob.get('protocol')!='vless':continue
        settings=ob.get('settings',{})
        node=settings if 'address' in settings else (settings.get('vnext') or [{}])[0]
        if node.get('address')!='127.0.0.1':continue
        stream=ob.get('streamSettings',{});opt=stream.get('sockopt',{})
        ref=opt.get('dialerProxy');leg=bytag.get(ref,{})
        dest=leg.get('settings',{}).get('redirect')
        if leg.get('protocol')!='freedom' or not isinstance(dest,str):continue
        if stream.get('security','none') not in ('','none') or stream.get('method',stream.get('network','tcp')) not in ('','tcp','raw','ws','websocket','httpupgrade','grpc','xhttp','splithttp','kcp','mkcp'):fail('relay_family_not_qualified')
        users=[settings] if node is settings else node.get('users',[])
        if len(users)!=1 or users[0].get('encryption','none') not in ('','none') or users[0].get('flow'):fail('relay_family_not_qualified')
        if set(opt)!={'dialerProxy'} or ob.get('proxySettings') or ob.get('sendThrough') or any(k in stream for k in ('address','port')):fail('relay_local_carrier_invalid')
        if 'finalmask' in stream and not relay_tcp_mask(stream['finalmask'],stream.get('method',stream.get('network','tcp'))):fail('relay_local_carrier_invalid')
        if set(leg)-{'tag','protocol','settings','streamSettings','sendThrough'} or set(leg.get('settings',{}))!={'redirect'} or set(leg.get('streamSettings',{}))-{'sockopt'}:fail('relay_carrier_invalid')
        host,sep,port=dest.rpartition(':');host=host.strip('[]')
        if not sep or not port.isdigit() or not 1<=int(port)<=65535 or int(port)!=node.get('port') or not host:fail('relay_destination_invalid')
        try:ip=ipaddress.ip_address(host)
        except ValueError:ip=None
        if ip is not None:
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:fail('relay_destination_invalid')
        else:
            if any(x in host for x in '/\\:@ '+chr(9)+chr(10)+chr(13)):fail('relay_destination_invalid')
        refs=[]
        def walk(x):
            if isinstance(x,dict):
                for key,value in x.items():
                    if key in ('dialerProxy','outboundTag','fallbackTag') and value==ref:refs.append(key)
                    if key=='proxySettings' and isinstance(value,dict) and value.get('tag')==ref:refs.append(key)
                    if key in ('selector','subjectSelector') and isinstance(value,list) and any(isinstance(v,str) and ref.startswith(v) for v in value):refs.append(key)
                    walk(value)
            elif isinstance(x,list):
                for value in x:walk(value)
        walk(config)
        if refs!=['dialerProxy'] or ref in remove:fail('relay_carrier_shared')
        node['address']=host
        if 'sockopt' in leg.get('streamSettings',{}):stream['sockopt']=copy.deepcopy(leg['streamSettings']['sockopt'])
        else:stream.pop('sockopt',None)
        if 'sendThrough' in leg:ob['sendThrough']=leg['sendThrough']
        remove.add(ref)
    c['outbounds']=[x for x in obs if x.get('tag') not in remove]
    return c
