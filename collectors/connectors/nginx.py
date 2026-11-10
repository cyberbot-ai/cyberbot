# Nginx profile v1. Parse configuration as data; never run nginx -t/-T or reload it.
NGINX_CONFIG = '/etc/nginx/nginx.conf'
NGINX_ROOT = '/etc/nginx'
NGINX_LOG_ROOT = '/var/log/nginx'
COMBINED = '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'
LATENCY_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000]


def nginx_configuration():
    import glob
    import shlex
    import stat
    seen = set(); consumed = 0; issues = []; formats = {'combined': COMBINED}
    access = []; errors = []; endpoints = []
    def read(path, depth=0):
        nonlocal consumed
        real = os.path.realpath(path)
        if depth > 12 or len(seen) >= 32 or not real.startswith(os.path.realpath(NGINX_ROOT)+'/'):
            issues.append('config_limit'); return []
        if real in seen: return []
        seen.add(real)
        try:
            fd = os.open(real, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd) as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise OSError()
                data = f.read(max(0, 131072-consumed)+1)
            consumed += len(data.encode())
            if consumed > 131072: issues.append('config_limit'); return []
            lexer = shlex.shlex(data, posix=True, punctuation_chars='{};')
            lexer.whitespace_split = True
            tokens = list(lexer)
            # shlex groups punctuation; quoted format literals must stay intact.
            tokens = [part for t in tokens for part in (list(t) if t and all(c in '{};' for c in t) else [t])]
            position = 0
            def block(level=0):
                nonlocal position
                if level > 32: raise ValueError()
                nodes = []; words = []
                while position < len(tokens):
                    token = tokens[position]; position += 1
                    if token == '}':
                        if words: raise ValueError()
                        return nodes
                    if token == '{':
                        nodes.append((words, block(level+1))); words = []
                    elif token == ';':
                        if words and words[0] == 'include' and len(words) == 2:
                            pattern = words[1] if os.path.isabs(words[1]) else os.path.join(NGINX_ROOT, words[1])
                            # Limit directory enumeration too; do not materialize all matches.
                            if not os.path.abspath(pattern).startswith(os.path.abspath(NGINX_ROOT)+'/'):
                                issues.append('config_limit'); words = []; continue
                            matches = __import__('itertools').islice(glob.iglob(pattern), 33)
                            for included in matches: nodes.extend(read(included, depth+1))
                        else: nodes.append((words, []))
                        words = []
                    else: words.append(token)
                if words: raise ValueError()
                return nodes
            return block()
        except (OSError, ValueError, UnicodeError):
            issues.append('config_unavailable'); return []
    tree = read(NGINX_CONFIG)
    def visit(nodes, server=None, location=None):
        for words, children in nodes:
            if not words: continue
            name = words[0]
            current_server = children if name == 'server' else server
            current_location = words if name == 'location' else location
            if name == 'log_format' and len(words) >= 3:
                parts = words[2:]
                if parts[0].startswith('escape='): parts = parts[1:]
                formats[words[1]] = ''.join(parts)
            if name == 'access_log' and len(words) >= 2:
                if words[1] == 'off': pass
                else:
                    access.append((words[1], words[2] if len(words)>2 and '=' not in words[2] else 'combined'))
                    if any(w.startswith(('if=', 'gzip')) for w in words[2:]): issues.append('access_filtered')
            if name == 'error_log' and len(words) >= 2: errors.append(words[1])
            if name == 'stub_status' and server is not None and location and len(location)==3 and location[1]=='=':
                # Probe only a simple exact status location, never a proxy/rewrite handler.
                allowed = {'stub_status','access_log','allow','deny','auth_basic','auth_basic_user_file','satisfy'}
                if any(w and w[0] not in allowed for w,_ in nodes) or any(w and w[0] in ('rewrite','return','if') for w,_ in server):
                    continue
                path = location[2]
                for listen, _ in server:
                    if listen and listen[0]=='listen' and len(listen)>=2 and 'ssl' not in listen:
                        match = re.fullmatch(r'(?:(?:127\.0\.0\.1|0\.0\.0\.0|\*):)?([0-9]{1,5})', listen[1])
                        if match and 1<=int(match.group(1))<=65535 and re.fullmatch(r'/[A-Za-z0-9_./-]{0,127}', path):
                            endpoints.append((int(match.group(1)), path))
            visit(children, current_server, current_location)
    visit(tree)
    def select(entries):
        accepted = []
        for path, fmt in entries:
            # Config cannot turn the collector into an arbitrary file reader.
            real = os.path.realpath(path)
            if not os.path.isabs(path) or '$' in path or not real.startswith(os.path.realpath(NGINX_LOG_ROOT)+'/'):
                issues.append('unsupported_log_path'); continue
            item = (real, fmt)
            if item not in accepted: accepted.append(item)
        if len(accepted)>1: issues.append('multiple_logs')
        return accepted[0] if accepted else None
    a = select(access); e = select([(p, '') for p in errors])
    return {'access': a, 'error': e, 'format': formats.get(a[1]) if a else None,
            'endpoint': endpoints[0] if endpoints else None, 'issues': sorted(set(issues)), 'bytes': consumed}


def nginx_fields(template, line):
    """Bounded deterministic scanner: no backtracking regex built from configuration."""
    parts = re.split(r'(\$[A-Za-z_][A-Za-z_0-9]*)', template)
    if len(parts)>257 or len(template)>4096: raise ValueError()
    if not line.startswith(parts[0]): raise ValueError()
    at = len(parts[0]); fields = {}
    for i in range(1, len(parts), 2):
        delimiter = parts[i+1]
        if not delimiter and i+2<len(parts): raise ValueError()
        end = line.find(delimiter, at) if delimiter else len(line)
        if end < 0: raise ValueError()
        fields[parts[i][1:]] = line[at:end]
        at = end+len(delimiter)
    if at != len(line): raise ValueError()
    return fields


def nginx_latency():
    return {'samples': 0, 'sumMs': 0.0, 'maxMs': 0.0, 'slow': 0, 'histogram': [0]*14}


def add_latency(stats, raw, slow_request_ms):
    try:
        value = float(raw)*1000
        if not __import__('math').isfinite(value) or not 0<=value<=86400000: return False
    except (ValueError, TypeError): return False
    stats['samples'] += 1; stats['sumMs'] += value; stats['maxMs'] = max(stats['maxMs'], value)
    stats['slow'] += int(value>=slow_request_ms)
    index = next((i for i,bound in enumerate(LATENCY_BUCKETS) if value<=bound),13)
    stats['histogram'][index] += 1
    return True


class NginxAnalysis(LogAnalysis):
    def __init__(self, request, clock=None, *, slow_request_ms=1000):
        super().__init__(request, clock)
        self.slow_request_ms = slow_request_ms
        self.statuses = collections.Counter(); self.request_time = nginx_latency(); self.upstream_time = nginx_latency()
        self.format = COMBINED

    def event(self, line, source, **unused):
        if source == 'access':
            try:
                fields = nginx_fields(self.format, line.rstrip('\r\n'))
                status = int(fields['status'])
                if not 100<=status<=599: raise ValueError()
                if 'time_local' in fields:
                    at = int(datetime.datetime.strptime(fields['time_local'], '%d/%b/%Y:%H:%M:%S %z').timestamp())
                elif 'time_iso8601' in fields: at = event_time(fields['time_iso8601'], self.now)
                elif 'msec' in fields: at = int(float(fields['msec']))
                else: raise ValueError()
                if at is None: raise ValueError()
                if at > self.now+300: self.gap('clock_changed', source); return
                if at < self.cutoff:
                    # Buffered logs can arrive late. Do not silently claim exact window rates.
                    if not self.initial: self.gap('late_records', source)
                    return
                self.statuses[str(status)] += 1; self.counts['requests'] += 1
                self.counts[str(status//100)+'xx'] += 1
                if 'request_time' in fields and not add_latency(self.request_time, fields['request_time'], self.slow_request_ms):
                    self.gap('timing_unavailable', source)
                if 'upstream_response_time' in fields:
                    for value in re.split(r'[, :]+', fields['upstream_response_time'])[:32]:
                        if value and value!='-' and not add_latency(self.upstream_time, value, self.slow_request_ms): self.gap('timing_unavailable',source)
            except (ValueError, KeyError, OverflowError):
                self.counts['unparsed'] += 1; self.gap('unknown_format', source)
        else:
            match = re.match(r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] \d+#\d+: (.*)', line)
            if not match: self.counts['unparsed'] += 1; self.gap('unknown_format', source); return
            try: at = int(datetime.datetime.strptime(match.group(1),'%Y/%m/%d %H:%M:%S').timestamp())
            except ValueError: self.gap('unknown_timestamp',source); return
            if at < self.cutoff: return
            if at > self.now+300: self.gap('clock_changed',source); return
            message = re.split(r', (?:client|server|request|upstream|host):', match.group(3), maxsplit=1)[0]; category = None
            for name, text in [('upstream_timeout','upstream timed out'),('upstream_connect','connect() failed'),('upstream_unavailable','no live upstreams'),('capacity','worker_connections are not enough')]:
                if text in message: category=name; break
            # Common probing/404/denied requests are statistics, never incidents.
            noise = any(s in message for s in ('No such file or directory','access forbidden by rule','client sent invalid','SSL_do_handshake() failed'))
            if noise: self.counts['client_noise'] += 1; return
            if category is None and match.group(2) in ('emerg','alert','crit'): category='critical_error'
            if category:
                self.counts[category] += 1
                if len(self.examples)<10: self.examples.append({'at':at,'category':category})
            elif match.group(2) == 'error': self.counts['other_errors'] += 1

    def status(self, config, generation):
        import http.client
        endpoint = config['endpoint']
        if endpoint is None: return None
        connection = http.client.HTTPConnection('127.0.0.1', endpoint[0], timeout=1.5)
        try:
            connection.request('GET', endpoint[1], headers={'Host':'127.0.0.1','Connection':'close'})
            response = connection.getresponse(); raw = response.read(4097)
            self.bytes_read += len(raw)
            if response.status!=200 or len(raw)>4096: return None
            m = re.fullmatch(rb'Active connections:\s*(\d+)\s+server accepts handled requests\s+(\d+)\s+(\d+)\s+(\d+)\s+Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)\s*', raw)
            if not m: return None
            values = [int(v) for v in m.groups()]
            if any(v>2**53-1 for v in values): return None
            result = dict(zip(('active','accepts','handled','requests','reading','writing','waiting'),values))
            # Persist counters only, never endpoint/configuration text.
            previous = self.state.get('status', {})
            self.next['status'] = {'requests':result['requests'],'generation':generation,'at':self.now}
            elapsed = self.now-previous.get('at', self.now)
            rps = None
            if generation and generation==previous.get('generation') and 0<elapsed<=3600:
                delta = result['requests']-previous.get('requests',result['requests'])
                if delta>=1: rps = (delta-1)/elapsed  # exclude this collector's one status request
                else: self.gap('counter_reset','status')
            result['rps'] = rps
            return result
        except (OSError, ValueError, http.client.HTTPException): return None
        finally: connection.close()


def nginx_detection():
    import shutil
    present = os.path.exists(NGINX_CONFIG) or shutil.which('nginx') is not None or os.path.isdir(NGINX_LOG_ROOT)
    generation = ''; service = 'unknown'
    try:
        pid = text('/run/nginx.pid').strip()
        if pid.isdigit() and text('/proc/'+pid+'/comm').strip()=='nginx':
            generation = hashlib.sha256((text('/proc/sys/kernel/random/boot_id',128)+pid+text('/proc/'+pid+'/stat').rsplit(')',1)[1].split()[19]).encode()).hexdigest()[:24]
            present = True; service = 'active'
    except (OSError, IndexError): pass
    if service!='active':
        try:
            result = subprocess.run(['systemctl','show','nginx.service','--property=LoadState,ActiveState'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            if result.returncode==0 and len(result.stdout)<1024:
                props = dict(line.split('=',1) for line in result.stdout.decode().splitlines() if '=' in line)
                if props.get('LoadState')=='loaded':
                    present = True
                    if props.get('ActiveState') in ('active','inactive','failed','activating','deactivating'): service=props['ActiveState']
        except (OSError, ValueError, subprocess.TimeoutExpired): pass
    return present, service, generation


def analyze_nginx(request, *, slow_request_ms=1000):
    a = NginxAnalysis(request, slow_request_ms=slow_request_ms)
    detected, service, generation = nginx_detection()
    config = nginx_configuration() if detected else {'access':None,'error':None,'format':None,'endpoint':None,'issues':[],'bytes':0}
    a.bytes_read += min(config['bytes'],131073)
    missing = []; stub = None
    if detected:
        for issue in config['issues']: a.gap(issue,'config')
        stub = a.status(config,generation)
        for source in ('access','error'):
            selected = config[source]
            if selected and (source!='access' or config['format']):
                if source=='access': a.format=config['format']
                # Changing configuration/format starts a fresh bounded window explicitly.
                signature = a.pseudonym(selected[0]+(a.format if source=='access' else ''))
                if a.state.get(source+'Signature') not in (None,signature):
                    a.state.get('files',{}).pop(source,None); a.gap('source_changed',source)
                a.next[source+'Signature']=signature
                a.file(source, selected[0])
            else: a.gap('source_unavailable',source)
        if not stub: missing.append('stub_status')
        if '$request_time' not in (config['format'] or ''): missing.append('request_time')
        if '$upstream_response_time' not in (config['format'] or ''): missing.append('upstream_response_time')
        if service=='unknown': missing.append('service_state')
    if not a.room(): a.gap('read_limit','all')
    elapsed = max(1,min(3600,a.now-a.cutoff))
    access_complete = 'access' in a.sources and not any(g['source'] in ('all','access','config') for g in a.gaps)
    error_complete = 'error' in a.sources and not any(g['source'] in ('all','error','config') for g in a.gaps)
    log_rps = a.counts['requests']/elapsed if access_complete and not a.initial else None
    return {'version':1,'at':a.now,'detected':detected,'service':service,
            'windowSeconds':elapsed,'coverage':{'complete':not a.gaps,'initial':a.initial,'sources':a.sources,'gaps':a.gaps},
            'accessComplete':access_complete,'errorComplete':error_complete,'missing':missing,
            'rps':stub['rps'] if stub and stub['rps'] is not None else log_rps,
            'rpsSource':'stub_status' if stub and stub['rps'] is not None else 'access_log',
            'status':stub,'counts':dict(a.counts),'statuses':dict(a.statuses),'requestTime':a.request_time,'upstreamTime':a.upstream_time,
            'examples':a.examples,'bytesRead':a.bytes_read,'durationMs':int((time.monotonic()-a.started)*1000),'nextState':a.next}


def collect_nginx(state):
    checkpoint = state.get('checkpoint')
    if state.get('config') is not None or not isinstance(checkpoint, dict) or set(checkpoint) - {'salt', 'interval', 'state'}:
        raise ValueError('Invalid log checkpoint')
    limits = collector_thresholds('nginx', state.get('thresholds', {}))
    return analyze_nginx(checkpoint, slow_request_ms=limits['slowRequestMs'])


def parse_access_status(line):
    match = re.search(r'"[A-Z]+ [^"\r\n]*"\s+(\d{3})\s+', line)
    return match.group(1) if match else None


class NginxWorkersAction:
    name = 'nginx_workers'
    config = '/etc/nginx/nginx.conf'
    binary = '/usr/sbin/nginx'
    service = '/usr/bin/systemctl'

    def validate_result(self, action, result):
        if result != {'workerProcesses': action['workerProcesses']}:
            raise ActionError('script_does_not_match_manifest')

    def validate(self, action):
        if set(action) != {'kind', 'workerProcesses', 'activation'} or action['kind'] != self.name:
            raise ActionError('unsupported_nginx_manifest')
        value = action['workerProcesses']
        if not isinstance(value, str) or value != 'auto' and (not re.fullmatch(r'[1-9][0-9]{0,2}', value) or int(value) > 128):
            raise ActionError('unsupported_worker_count')
        if action['activation'] not in ('none', 'reload', 'restart'):
            raise ActionError('unsupported_activation')

    def _source(self):
        # Default instance only. No user-supplied file, prefix, unit, binary or args.
        parent = os.lstat(os.path.dirname(self.config))
        binary = os.lstat(self.binary)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise ActionError('unsafe_nginx_directory')
        if not stat.S_ISREG(binary.st_mode) or binary.st_uid != 0 or binary.st_mode & 0o022:
            raise ActionError('unsafe_nginx_binary')
        source, meta = _action_read(self.config)
        if meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ActionError('unsafe_nginx_config')
        return source, meta

    def _tokens(self, source):
        text = source.decode('utf-8', errors='strict')
        tokens = []
        # Full lexer: never match worker_processes inside comments, strings or a block.
        i = 0
        while i < len(text):
            if text[i].isspace():
                i += 1
                continue
            start = i
            if text[i] == '#':
                end = text.find('\n', i)
                i = len(text) if end < 0 else end + 1
                continue
            if text[i] in '{};':
                i += 1
            elif text[i] in "'\"":
                quote = text[i]
                i += 1
                while i < len(text) and text[i] != quote:
                    i += 2 if text[i] == '\\' else 1
                if i >= len(text):
                    raise ActionError('invalid_nginx_syntax')
                i += 1
            else:
                while i < len(text) and not text[i].isspace() and text[i] not in '{};#':
                    if text[i] in "'\"\\":
                        raise ActionError('ambiguous_nginx_token')
                    i += 1
            tokens.append((text[start:i], start, i))
        return text, tokens

    def _replace(self, source, value):
        text,tokens=self._tokens(source)
        depth, matches = 0, []
        for index, (token, start, end) in enumerate(tokens):
            if token == '{':
                depth += 1
            elif token == '}':
                depth -= 1
                if depth < 0:
                    raise ActionError('invalid_nginx_syntax')
            elif token == 'worker_processes' and depth == 0:
                if index + 2 >= len(tokens) or tokens[index + 2][0] != ';' or not re.fullmatch(r'auto|[1-9][0-9]*', tokens[index + 1][0]):
                    raise ActionError('ambiguous_worker_directive')
                matches.append(tokens[index + 1])
        if depth != 0 or len(matches) != 1:
            raise ActionError('single_worker_directive_required')
        before, start, end = matches[0]
        return (text[:start] + value + text[end:]).encode(), before

    def prepare(self, action):
        self.validate(action)
        if os.geteuid() != 0:
            raise ActionError("nginx_root_required")
        source, meta = self._source()
        candidate, before = self._replace(source, action['workerProcesses'])
        unit_hash=self._unit() if action['activation']=='restart' else None
        if action['activation']!='none':
            fd=self._master()
            os.close(fd)
        return {'kind': self.name, 'restartUnitHash':unit_hash, 'configHash': _action_hash(source),
                'resultHash': _action_hash(candidate), 'mode': stat.S_IMODE(meta.st_mode),
                'uid': meta.st_uid, 'gid': meta.st_gid,
                'before': 'worker_processes ' + before + ';',
                'after': 'worker_processes ' + action['workerProcesses'] + ';',
                'writes': [self.config, 'private backup and execution receipt', 'Nginx diagnostic logs'],
                'activation': action['activation'],
                'rollback': 'Restore exact backup only while current config hash matches; reload/restart may interrupt connections and cannot restore lost work'}

    def _master(self):
        # Pin the default instance through a pidfd; never signal a model-supplied PID.
        source, _ = self._source()
        _,tokens=self._tokens(source)
        depth,pids=0,[]
        for index,(token,_,_) in enumerate(tokens):
            if token=='{': depth+=1
            elif token=='}': depth-=1
            elif token=='pid' and depth==0 and index+2<len(tokens) and tokens[index+2][0]==';': pids.append(tokens[index+1][0])
        if pids!=['/run/nginx.pid']: raise ActionError('default_nginx_pid_required')
        data, meta = _action_read('/run/nginx.pid',32)
        if meta.st_uid!=0 or not re.fullmatch(rb'[1-9][0-9]{0,9}\s*',data):
            raise ActionError('invalid_nginx_pid')
        pid=int(data)
        if pid<=1 or not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
            raise ActionError('pidfd_unavailable')
        fd=os.pidfd_open(pid,0)
        try:
            if os.readlink('/proc/'+str(pid)+'/exe') != self.binary:
                raise ActionError('nginx_master_mismatch')
            signal.pidfd_send_signal(fd,0,None,0)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _unit(self):
        if not os.path.isdir('/run/systemd/system'):
            raise ActionError('systemd_restart_unavailable')
        metadata=dict(line.split('=',1) for line in _action_capture([self.service,'show','nginx.service','--no-pager','-p','FragmentPath','-p','DropInPaths','-p','LoadState']).splitlines() if '=' in line)
        if metadata.get('LoadState')!='loaded' or metadata.get('DropInPaths') or metadata.get('FragmentPath') not in ('/lib/systemd/system/nginx.service','/usr/lib/systemd/system/nginx.service'):
            raise ActionError('nginx_unit_not_reviewed')
        data, meta=_action_read(metadata['FragmentPath'],16384)
        digest=_action_hash(data)
        if meta.st_uid!=0 or meta.st_mode & 0o022 or digest not in ('88965b52766830e7d94fa5871c43afe8f989df0849e4873abf8de22ee80fc4ac',):
            raise ActionError('nginx_unit_not_reviewed')
        return digest

    def _activate(self, activation, unit_hash=None):
        if activation == 'none': return True
        try:
            if activation == 'restart':
                if self._unit()!=unit_hash: return False
                return _action_fixed([self.service,'restart','nginx.service'])
            fd=self._master()
            try: signal.pidfd_send_signal(fd,signal.SIGHUP,None,0)
            finally: os.close(fd)
            return True
        except (OSError,ValueError):
            return False

    def apply(self, action, prepared, directory):
        if prepared != self.prepare(action):
            raise ActionError('nginx_config_changed')
        source, meta = self._source()
        candidate, _ = self._replace(source, action['workerProcesses'])
        _action_write(os.path.join(directory, 'before.conf'), source)
        staging = self.config + '.cyberbot-candidate'
        if os.path.lexists(staging):
            raise ActionError('nginx_staging_exists')
        try:
            _action_write(staging, candidate, stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
            if not _action_fixed([self.binary, '-t', '-c', staging]):
                raise ActionError('nginx_validation_failed')
        finally:
            try:
                os.unlink(staging)
            except FileNotFoundError:
                pass
        # Compare again after validation, before the only configuration write.
        if self.prepare(action) != prepared:
            raise ActionError('nginx_config_changed')
        _action_write(self.config, candidate, stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
        if self._activate(action['activation'],prepared.get('restartUnitHash')) and self.verify(prepared['resultHash'],action['activation']):
            return {'changed': source != candidate, 'verified': True, 'configHash': prepared['resultHash'], 'rollbackAvailable': source != candidate, 'runtimeHealth':'not_checked'}
        restored = self.rollback(action, prepared, directory)
        return {'changed': True, 'verified': False, 'rollbackVerified': restored['verified'], 'error': 'activation_or_verification_failed'}

    def verify(self, expected, activation='none'):
        source, _ = self._source()
        if _action_hash(source)!=expected or not _action_fixed([self.binary,'-t','-c',self.config]): return False
        if activation!='none':
            try:
                fd=self._master()
                os.close(fd)
            except (OSError,ValueError): return False
        return True

    def rollback(self, action, prepared, directory):
        current, meta = self._source()
        if _action_hash(current) != prepared['resultHash']:
            raise ActionError('rollback_config_changed')
        before, _ = _action_read(os.path.join(directory, 'before.conf'))
        if _action_hash(before) != prepared['configHash']:
            raise ActionError('rollback_backup_changed')
        _action_write(self.config, before, stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
        activated = self._activate(action['activation'],prepared.get('restartUnitHash'))
        return {'changed': True, 'verified': activated and self.verify(prepared['configHash'],action['activation']), 'configHash': prepared['configHash']}


NGINX_ADAPTER = ServiceAdapter(
    IdentityPolicy('nginx'),
    collect_nginx,
    structured=True, coverage=lambda data: data['coverage']['complete'],
    actions=(NginxWorkersAction(),),
)
