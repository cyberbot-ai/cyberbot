export interface Endpoint { host: string; user: string; port: number; identityFile: string | null; jumpHost: string | null }
export interface Disk { mount: string; usedPercent: number; inodePercent: number | null }
export interface LinuxPlatform {version:number;distro:string;release:string;versionId:string;idLike:string[];family:string;architecture:string;kernel:string;procfs:boolean;initSystem:string;serviceAdapter:string;journalAvailable:boolean;packageManager:string;packageAdapter:string;advisoryProvider:string}
export interface Observation { platform?:LinuxPlatform|null; at: number; cpuPercent: number | null; memoryPercent: number | null; swapPercent: number | null; load: number | null; uptime: number | null; disks: Disk[]; services: {name: string; state: string}[]; missing: string[]; bytesReceived: number; durationMs: number }
export interface VulnerabilityCard {hiddenCount?:number;status:Health;affected:number;critical:number;at:number|null}
export interface Server { networkOffline?:boolean; awaitingFirstCheck?:boolean; monitoring?:MonitoringValues; services?:ServiceCard[]; checkStatus?:Health; vulnerabilities?:VulnerabilityCard; logStatus?:Health; id: string; sourceId: string; name: string; endpoint: Endpoint; observation: Observation | null; lastError: string | null; lastAttempt: number | null; nextCheck: number; failures: number }
export interface Source { id: string; name: string; kind: string; location: string; lastSync: number | null; error: string | null }
export interface InventoryFile { name: string; location: string }
export interface Incident {resolvedByUserAt?:number|null;manualResolutionPending?:boolean; episode?:string; id: string; serverId: string; check: string; title: string; severity: string; status: string; openedAt: number; updatedAt: number; evidence: string }
export interface Settings { connectivityProbe?:{host:string;backupHost:string|null}; mode: 'manual' | 'auto'; dailyRunLimit: number | null; dailyTokenLimit: number | null; runTokenLimit: number; autoAgent: 'codex' | 'claude'; pollSeconds: number; logPollSeconds:number; concurrency: number; paused: boolean; dockBadgeEnabled: boolean }
export interface Snapshot { offline?:boolean; awaitingFirstCheck?:string[]; pendingActions?:number;monitoring?:Record<string,MonitoringValues>; services?:Record<string,ServiceCard[]>; checkStatus?:Record<string,Health>; vulnerabilities?:Record<string,VulnerabilityCard>; logStatus: Record<string,Health>; servers: Server[]; sources: Source[]; incidents: Incident[]; settings: Settings; collectedAt: number }
export interface AgentStatus { name: string; path: string | null; version: string | null; ready: boolean; reason: string }
export type Health = 'healthy' | 'warning' | 'critical' | 'unknown' | 'stale' | 'unreachable';

export interface Investigation { chat?:{id:string;title:string;turn:number;scope?:'server'|'fleet'}|null;authoringId?:string|null;modelProfile?:AiSelection|null;actualModel?:string|null; groupId?:string|null; origin?:string; usageComplete?:boolean; id:string; agent:string; serverIds:string[]; question:string; status:string; startedAt:number; endedAt:number|null; text:string; error:string|null; usage:Record<string,unknown>|null; audit:{at:number;tool:string;ok:boolean}[]; sessionId:string|null }

export interface AutoJob { groupId?:string|null; id:string; incidentId:string; serverId:string; title:string; evidence:string; severity:string; occurrences:number; state:string; createdAt:number; notBefore:number; runId:string|null }
export interface AutoStatus { day:number; runs:number; actualTokens:number; chargedTokens:number; reservedTokens:number; uncertainRuns:number; blockedReason:string|null; waitingReason:string|null; queued:number; jobs:AutoJob[] }

export interface LogSummary { sshCorrelationLimited?:boolean; id:string; at:number; remoteAt:number; windowSeconds:number; coverage:{complete:boolean;initial:boolean;sources:string[];gaps:{reason:string;source:string;fromTime?:number;toTime?:number;fromOffset?:number;toOffset?:number}[]}; counts:Record<string,number>; examples:{at:number;category:string;template:string;peer?:string;account?:string}[]; findings:{check:string;title:string;severity:string;count:number}[]; learning:boolean; bytesRead:number;bytesReceived:number;durationMs:number }
export interface LogCoveragePeriod {remoteAt:number;windowSeconds:number;gaps:LogSummary['coverage']['gaps']}
export interface LogView {shortCheck:boolean;lastIncomplete:LogCoveragePeriod|null;monitoring?:MonitoringValues;summary:LogSummary|null;findingExamples?:Record<string,{at:number;source:string;text:string}>;severity?:string|null;lastSuccess:number|null;nextCheck:number;error:string|null;fresh:boolean}


export interface StorageStatus {actions?:{bytes:number;limitBytes:number;records:number;active:number;historyDays:number};activity?:ActivityStorage;databaseBytes:number;walBytes:number;limitBytes:number;cacheBytes:number;cacheLimitBytes:number;blocked:boolean;message:string|null}
export interface VulnerabilityEvaluation {at:number;root:string;checks:number;freshUntil:number;coverage:string[];generations:Record<string,string>;affected:number;critical:number;unknown:number;error:string|null}
export interface VulnerabilityFinding {fingerprint:string;hiddenAt?:number|null;source:string;cve:string;state:string;severity:string;severitySource:string;packages:{name:string;version:string;fixedVersion:string|null}[];description:string;url:string;reason:string|null;fixPublished:boolean}
export interface VulnerabilityBulkFix {findingCount:number;packages:string[];hasUnverified:boolean}
export interface VulnerabilityView {aptError?:string|null;active?:{affected:number;critical:number;unknown:number;hidden:number};hiddenCount?:number;monitoring?:MonitoringValues;evaluation:VulnerabilityEvaluation|null;fresh:boolean;collecting:boolean;assessmentPending?:boolean;lastSuccess:number|null;nextCheck:number;error:string|null;total:number;offset:number;findings:VulnerabilityFinding[];fixes:Record<string,string>;bulkFix?:VulnerabilityBulkFix;sources:AdvisorySource[];cvssQueue?:CvssQueue}
export interface CvssQueue {total:number;waiting:number;unavailable:number;pausedUntil:number|null;budgetExhausted:boolean;etaSeconds:number|null;overflow:boolean}

export interface AdvisorySource {id:string;checkedAt:number|null;error:string|null}


export interface LocalResourceSample {cpuPercent:number|null;memoryBytes:number|null;rxBytes:number|null;txBytes:number|null;durationMs:number}
export interface ConnectorConfig {enabled:boolean;autoEndpoint?:boolean;endpoint:string;port:number;user:string;intervalSeconds:number;expectedPeers:number;expectReplica:boolean}
export interface ConnectorSpec {unixSocketName?:string;panel?:string;mutationKind?:string;actionPresentation?:string;activityLabels?:Record<string,string>;multiple:boolean;replication:boolean;instanceCredentials?:string;profileDefaults?:Record<string,unknown>;preferred?:boolean;units?:string[];hideUnits?:boolean;reportsAvailability?:boolean;scopeInstances?:boolean;incidentNamespace?:string;actions:string[];name:string;endpoint:string;endpoints:string[];port:number;credentials:string;rights:string;metrics:{key:string;label:string;unit:string;rule?:{threshold:number;critical:number|null;mode:string}}[]}
export type ServiceAvailability = 'running' | 'stopped' | 'unknown';
export interface ConnectorSummary {id:string;at:number;bytesReceived:number;data:{availability?:ServiceAvailability;detected:boolean;connected:boolean;complete:boolean;issues:string[];metrics:Record<string,number|null>;durationMs:number};rates:Record<string,number|null>;findings:{key:string;title:string;severity:string;value:number}[]}
export interface ServiceDeviation {key:string;title:string;severity:string;value:number|null;threshold:number;at:number;pending:boolean;recovering:boolean}
export interface ConnectorView {availability?:ServiceAvailability;monitoring?:MonitoringValues;kind:string;config:ConnectorConfig;summary:ConnectorSummary|null;evidence:ConnectorSummary[];deviations?:ServiceDeviation[];error:string|null;fresh:boolean;status:string;nextCheck:number}
export interface ServiceCard {availability?:ServiceAvailability;metric?:{value:number;unit:string};instanceId?:string;kind:string;name:string;detected?:boolean;status:string;at:number|null}

export interface ServiceInstance {id:string;kind:string;name:string;canAdd:boolean;canRemove:boolean}

export interface IncidentGroup {id:string;key:string;title:string;reason:string;openedAt:number;createdAt:number;updatedAt:number;closedAt:number|null;status:string;severity:string;memberCount:number;serverCount:number;removedMembers:number;autoState:string|null;runId:string|null;dispatchedAt:number|null}
export interface GroupMember {incident:Incident;serverName:string;serverAddress?:string;joinedAt:number;truncated:boolean}
export interface GroupView {group:IncidentGroup;members:GroupMember[];total:number;offset:number;nextOffset:number|null;dependencies?:[string,string][];dependenciesTruncated?:boolean;fresh:number;open:number;outsideScope:number}
export interface ServerDependencies { available:{id:string;name:string;host?:string;address?:string}[]; dependsOn:string[] }
export interface NotificationStatus {enabled:boolean;badgeAllowed:boolean;permission:string;error:string|null;queued:number;overflow:number}

export interface ActivityStorage {bytes:number;limitBytes:number;dropped:number;error:string|null}
export interface ActivityEvent {aiAction?:{requestId:string;artifactHash:string;rules:string;provider:string;model:string;effort:string;state:string;tokens:number|null;goal?:string};monitoring?:MonitoringExecution;id:string;at:number;category:string;action:string;phase:string;operationId:string;target:string|null;server?:{id?:string;name:string;address:string}|null;runId:string|null;durationMs:number|null}
export interface ActivityPage {events:ActivityEvent[];next:string|null;expired:boolean;skipped:number;storage:ActivityStorage}

export interface ActivityQuery {definitionId?:string|null;before?:string|null;category?:string|null;phase?:string|null;search?:string|null}

export type MonitoringThresholds = Record<string, Record<string, number>>;
export interface MonitoringThresholdField {key:string;label:string;unit:string;default:number;min:number;max:number;integer:boolean}
export interface MonitoringThresholdRule {key:string;label:string;fields:MonitoringThresholdField[]}
export interface MonitoringValues {enabled:boolean;intervalSeconds:number;diagnosticEnabled:boolean;expectedPeers:number;expectReplica:boolean;thresholds?:MonitoringThresholds}
export type MonitoringScalarField = Exclude<keyof MonitoringValues, 'thresholds'>;
export type MonitoringOverrides = {[K in MonitoringScalarField]?:MonitoringValues[K]|null} & {thresholds?:MonitoringThresholds};
export interface MonitoringScope {definitionId:string;serverId:string|null;instanceId:string|null}
export interface MonitoringPolicy {inherited?:MonitoringValues;values:MonitoringValues;overrides:MonitoringOverrides;origins:Record<MonitoringScalarField,string>;thresholdOrigins?:Record<string,string>;revision:number}
export interface MonitoringLibraryEntry {values:MonitoringValues;serverOverride:boolean;instanceOverrides:Record<string,MonitoringValues>}
export interface MonitoringDefinition {id:string;name:string;category:string;runner:string;place:string;purpose:string;reads:string;commands:string;writes:string;rights:string;limits:string;schedule:string;configurable:boolean;intervalEditable:boolean;diagnostics:boolean;replication:boolean;factoryInterval:number;version:string;thresholds?:MonitoringThresholdRule[]}
export interface MonitoringExecution {serverId?:string|null;definitionId:string;version:string;trigger:string;instanceId:string|null;revision:number}
export interface MonitoringTarget {definitionId:string;serverId?:string|null;instanceId?:string|null}

export interface AiModelProfile {model:string;effort:string}
export interface AiProfiles {revision:number;providers:Record<string,Record<string,AiModelProfile>>}
export interface AgentModel {id:string;name:string;efforts:string[];resolvedModel:string|null}
export interface AiSelection {revision:number;alias:string;primary:AiModelProfile;low:AiModelProfile}

export type SupervisedAction = {kind:'diagnostic'} | {kind:'shell'} | {kind:'nginx_workers';workerProcesses:string;activation:'none'|'reload'|'restart'};
export interface ActionReview {durationMs?:number;id:string;verdict:{decision:'allow'|'confirm'|'deny'|'uncertain';explanation:string;effects:string[]};model:string|null;usage:Record<string,unknown>;usageComplete:boolean;tokens:number}
export interface ActionCard {id:string;runId:string;serverId:string;serverLabel:string;goal:string;state:string;createdAt:number;expiresAt:number;action:SupervisedAction;review:ActionReview|null;artifactHash:string;error:string|null;sessionGranted:boolean}
export interface ActionRequest {id:string;runId:string;serverId:string;serverLabel:string;state:string;createdAt:number;expiresAt:number;artifactHash:string;review:ActionReview|null;decision:string|null;result:Record<string,unknown>|null;error:string|null;artifact:{runId:string;scopeEndpoints:Record<string,string>;rules:string;provider:string;profile:AiSelection;endpoint:string;spec:{serverId:string;goal:string;code:string;inputs:unknown[];action:SupervisedAction;rollbackPlan:string};inputs:unknown;prepared:{before?:string;after?:string;[key:string]:unknown};isolation:Record<string,unknown>}}
