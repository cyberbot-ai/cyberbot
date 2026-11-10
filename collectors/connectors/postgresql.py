# PostgreSQL v1: fixed catalog queries, local endpoints only, no raw SQL text.
PG_META = """SELECT pg_catalog.json_build_object(
 'version',current_setting('server_version_num')::int,
 'generation',extract(epoch from pg_catalog.pg_postmaster_start_time())::bigint,
 'fullStats',pg_catalog.pg_has_role(current_user,'pg_read_all_stats','USAGE'),
 'superuser',current_setting('is_superuser')='on',
 'trackActivities',current_setting('track_activities')='on',
 'trackCounts',current_setting('track_counts')='on',
 'recovery',pg_catalog.pg_is_in_recovery());"""
PG_STATS = """WITH activity AS MATERIALIZED (
 SELECT pid,backend_type,state,query_start,xact_start FROM pg_catalog.pg_stat_activity WHERE pid<>pg_catalog.pg_backend_pid()
), waits AS MATERIALIZED (
 SELECT pid,min(waitstart) AS started FROM pg_catalog.pg_locks WHERE NOT granted AND pid IS NOT NULL GROUP BY pid
), replication AS MATERIALIZED (
 SELECT state,replay_lsn FROM pg_catalog.pg_stat_replication
), position AS (
 SELECT CASE WHEN pg_catalog.pg_is_in_recovery() THEN pg_catalog.pg_last_wal_receive_lsn() ELSE pg_catalog.pg_current_wal_lsn() END AS lsn
)
SELECT pg_catalog.json_build_object(
 'version',current_setting('server_version_num')::int,
 'generation',extract(epoch from pg_catalog.pg_postmaster_start_time())::bigint,
 'recovery',pg_catalog.pg_is_in_recovery(),
 'fullStats',pg_catalog.pg_has_role(current_user,'pg_read_all_stats','USAGE'),
 'trackActivities',current_setting('track_activities')='on',
 'trackCounts',current_setting('track_counts')='on',
 'connections',(SELECT count(*) FROM activity WHERE backend_type='client backend'),
 'maxConnections',current_setting('max_connections')::int,
 'reservedConnections',current_setting('superuser_reserved_connections')::int+coalesce(current_setting('reserved_connections',true),'0')::int,
 'active',(SELECT count(*) FROM activity WHERE backend_type='client backend' AND state='active'),
 'disabledActivities',(SELECT count(*) FROM activity WHERE state='disabled'),
 'longQueries',(SELECT count(*) FROM activity WHERE backend_type='client backend' AND state='active' AND query_start<statement_timestamp()-interval '{longQuerySeconds} seconds'),
 'longestQuerySeconds',(SELECT coalesce(max(greatest(0,extract(epoch from statement_timestamp()-query_start))),0) FROM activity WHERE backend_type='client backend' AND state='active'),
 'idleTransactions',(SELECT count(*) FROM activity WHERE state IN ('idle in transaction','idle in transaction (aborted)') AND xact_start<statement_timestamp()-interval '{idleTransactionSeconds} seconds'),
 'blocked',(SELECT count(*) FROM waits),
 'unknownWaits',(SELECT count(*) FROM waits WHERE started IS NULL),
 'maxWaitSeconds',(SELECT coalesce(max(greatest(0,extract(epoch from statement_timestamp()-started))),0) FROM waits),
 'blockers',(SELECT coalesce(json_agg(json_build_object('pid',pid,'blockers',ARRAY(SELECT p FROM unnest(pg_catalog.pg_blocking_pids(pid)) p LIMIT 8))), '[]') FROM (SELECT pid FROM waits ORDER BY started NULLS LAST LIMIT 5) b),
 'streaming',(SELECT count(*) FROM replication WHERE state='streaming'),
 'replicationUnknown',(SELECT count(*) FROM replication WHERE replay_lsn IS NULL),
 'replicaBacklogBytes',(SELECT max(greatest(0,pg_catalog.pg_wal_lsn_diff(position.lsn,replication.replay_lsn))) FROM position,replication),
 'receiver',(SELECT count(*) FROM pg_catalog.pg_stat_wal_receiver WHERE status='streaming'),
 'replayBacklogBytes',CASE WHEN pg_catalog.pg_is_in_recovery() AND pg_catalog.pg_last_wal_receive_lsn() IS NOT NULL AND pg_catalog.pg_last_wal_replay_lsn() IS NOT NULL THEN greatest(0,pg_catalog.pg_wal_lsn_diff(pg_catalog.pg_last_wal_receive_lsn(),pg_catalog.pg_last_wal_replay_lsn())) ELSE NULL END,
 'replayPaused',CASE WHEN pg_catalog.pg_is_in_recovery() THEN pg_catalog.pg_is_wal_replay_paused() ELSE false END,
 'slotRetainedBytes',(SELECT max(greatest(0,pg_catalog.pg_wal_lsn_diff(position.lsn,s.restart_lsn))) FROM pg_catalog.pg_replication_slots s,position),
 'inactiveSlots',(SELECT count(*) FROM pg_catalog.pg_replication_slots WHERE NOT active),
 'autovacuumWorkers',(SELECT count(*) FROM activity WHERE backend_type='autovacuum worker'),
 'xidAge',(SELECT max(greatest(0,age(datfrozenxid))) FROM pg_catalog.pg_database),
 'deadlocks',(SELECT coalesce(sum(deadlocks),0) FROM pg_catalog.pg_stat_database),
 'rollbacks',(SELECT coalesce(sum(xact_rollback),0) FROM pg_catalog.pg_stat_database));"""

PG_ENDPOINTS = ('/var/run/postgresql','/tmp','127.0.0.1','::1')

def pg_config(raw):
    defaults={'enabled':False,'autoEndpoint':False,'host':'/var/run/postgresql','port':5432,'database':'postgres','user':'','intervalSeconds':180,'expectedStreaming':0,'expectReceiver':False}
    if not isinstance(raw,dict) or set(raw)-set(defaults):raise ValueError('PostgreSQL profile')
    c=dict(defaults,**raw)
    if any(type(c[key])!=bool for key in ('enabled','autoEndpoint','expectReceiver')) or not (c['host'] in PG_ENDPOINTS or literal_ip(c['host'])):raise ValueError('PostgreSQL endpoint')
    for key,low,high in [('port',1,65535),('intervalSeconds',60,86400),('expectedStreaming',0,64)]:
        if type(c[key])!=int or not low<=c[key]<=high:raise ValueError('PostgreSQL limit')
    for key in ('database','user'):
        if key=='user' and c[key]=='':continue
        if not isinstance(c[key],str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,62}',c[key]):raise ValueError('PostgreSQL name')
    return c

def pg_query(config,sql):
    # libpq may use the existing SSH account's .pgpass; no password enters argv/JSON.
    home=pwd.getpwuid(os.getuid()).pw_dir
    env={'PATH':'/usr/bin:/bin','HOME':home,'LC_ALL':'C','PGCONNECT_TIMEOUT':'2',
         'PGAPPNAME':'cyberbot_diagnostics','PGPASSFILE':os.path.join(home,'.pgpass'),
         'PGOPTIONS':'-c default_transaction_read_only=on -c statement_timeout=1500 -c lock_timeout=250 -c idle_in_transaction_session_timeout=2000 -c search_path=pg_catalog -c work_mem=256kB -c jit=off'}
    args=['/usr/bin/psql','-X','-w','-q','-t','-A','--set=ON_ERROR_STOP=1','--host='+config['host'],'--port='+str(config['port']),'--dbname='+config['database']]
    if config['user']:args+=['--username='+config['user']]
    proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    out=bytearray();errors=bytearray();deadline=time.monotonic()+5
    try:
        proc.stdin.write(('BEGIN READ ONLY;\n'+sql+'\nROLLBACK;\n').encode());proc.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ,out);selector.register(proc.stderr,selectors.EVENT_READ,errors)
            while selector.get_map():
                if time.monotonic()>deadline:raise ValueError('query_timeout')
                for key,_ in selector.select(0.1):
                    data=os.read(key.fd,4096)
                    if not data:selector.unregister(key.fileobj);continue
                    key.data.extend(data)
                    if len(out)>16384 or len(errors)>4096:raise ValueError('query_output_limit')
        if proc.wait(timeout=1)!=0:raise ValueError('connection_or_query_denied')
        return load_collector_json(out)
    finally:
        if proc.poll() is None:proc.kill()
        proc.wait(timeout=1);proc.stdout.close();proc.stderr.close()
        if not proc.stdin.closed:proc.stdin.close()

def pg_owned_endpoint(config, records, scan_complete):
    host, port = config['host'], config['port']
    if not host.startswith('/'):
        return owned_listener('postgresql', host, port, records)
    path = '{}/.s.PGSQL.{}'.format(host, port)
    canonical = os.path.realpath(path)
    if any(record['complete'] and any(os.path.realpath(s) == canonical for s in record['sockets'])
           for record in records):
        return True
    if scan_complete and all(record['complete'] for record in records):
        return False

    # Unprivileged SSH accounts may be unable to read another user's descriptor table.
    # For Unix sockets Linux can identify the actual peer before any SQL is sent.
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(path)
            size = struct.calcsize('iII')
            pid, uid, _ = struct.unpack('iII', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))
            if pid <= 0 or text('/proc/{}/comm'.format(pid), 64).strip() not in ('postgres', 'postmaster'):
                return False
            try:
                name = os.path.basename(os.readlink('/proc/{}/exe'.format(pid))).split(' (deleted)', 1)[0]
                return name in ('postgres', 'postmaster')
            except PermissionError:
                return uid == pwd.getpwnam('postgres').pw_uid
    except (OSError, KeyError, AttributeError):
        return False


def analyze_postgresql(request):
    started=time.monotonic();config=pg_config(request.get('state',{}))
    limits = collector_thresholds('postgresql', request.get('thresholds', {}))
    records, scan_complete = service_runtime(kind_filter='postgresql', details=True)
    detected = any(record['verified'] for record in records)
    result={'version':1,'detected':detected,'connected':False,'coverage':False,'issues':[], 'meta':None,'metrics':None,'durationMs':0}
    if not config['enabled']:
        result['issues']=['profile_disabled'] if detected else []
    elif config['autoEndpoint'] and scan_complete and not records:
        pass
    else:
        try:
            if config['autoEndpoint']:
                config['host'], config['port'] = discovered_endpoint('postgresql', PG_ENDPOINTS[0], 5432, PG_ENDPOINTS, records)
            if not pg_owned_endpoint(config, records, scan_complete):
                raise ValueError('endpoint_not_local')
            result['detected'] = True
            if not os.path.isfile('/usr/bin/psql'):
                raise ValueError('psql_missing')
            meta=pg_query(config,PG_META);result.update(detected=True,connected=True,meta=meta)
            if not 140000<=meta['version']<190000:result['issues']=['unsupported_version']
            elif not meta['fullStats']:result['issues']=['read_all_stats_required']
            else:
                metrics=pg_query(config,PG_STATS.format(**limits))
                if any(metrics[k]!=meta[k] for k in ('version','generation','recovery','fullStats','trackActivities','trackCounts')):raise ValueError('instance_changed')
                result['metrics']=metrics
                if not meta['trackActivities'] or metrics['disabledActivities']:result['issues'].append('activity_incomplete')
                if not meta['trackCounts']:result['issues'].append('counters_disabled')
                if metrics['unknownWaits']:result['issues'].append('lock_wait_age_unknown')
                if metrics['replicationUnknown'] or meta['recovery'] and metrics['replayBacklogBytes'] is None:result['issues'].append('replication_position_unknown')
                result['coverage']=not result['issues']
        except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as e:
            # Never forward stderr, role names, DSNs or server-controlled error text.
            reason=str(e) if isinstance(e,ValueError) and str(e) in ('query_timeout','query_output_limit','connection_or_query_denied','instance_changed','endpoint_not_local','endpoint_ambiguous','psql_missing') else 'collection_failed'
            result['issues']=[reason];result['coverage']=False;result['metrics']=None
    result['durationMs']=int((time.monotonic()-started)*1000)
    return result


def pg_unix_endpoint(path, port, allowed):
    folder, separator, number = path.rpartition('/.s.PGSQL.')
    if not separator:
        return fixed_unix_endpoint(path, port, allowed)
    if folder == '/run/postgresql':
        folder = '/var/run/postgresql'
    if folder in allowed and number.isdecimal() and 0 < int(number) <= 65535:
        return folder, int(number)
    return None


def collect_postgresql(state):
    if state.get('checkpoint') is not None:
        raise ValueError('Invalid database checkpoint')
    config = state['config']
    if not isinstance(config, dict):
        raise ValueError('Invalid database profile')
    aliases = {'endpoint': 'host', 'expectedPeers': 'expectedStreaming', 'expectReplica': 'expectReceiver'}
    return analyze_postgresql({
        'state': {aliases.get(key, key): value for key, value in config.items()},
        'thresholds': state.get('thresholds', {}),
    })


POSTGRESQL_ADAPTER = ServiceAdapter(
    IdentityPolicy('postgres', 'postmaster', socket_pattern=r'/(?:var/run/postgresql|run/postgresql|tmp)/\.s\.PGSQL\.[0-9]{1,5}', process_limit=1024, unix_endpoint=pg_unix_endpoint),
    collect_postgresql,
    structured=True, coverage=lambda data: data['coverage'],
)
