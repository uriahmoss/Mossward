package store

import (
	"errors"
	"time"

	"mossward/internal/model"
)

var ErrNotFound = errors.New("scan not found")
var ErrIdentityNotFound = errors.New("identity not found")
var ErrAlreadyInitialized = errors.New("Mossward has already been initialized")
var ErrCeremonyNotFound = errors.New("authentication ceremony not found")
var ErrFinalAdministrator = errors.New("cannot remove the final active local administrator")
var ErrInvalidEnrollmentToken = errors.New("endpoint enrollment token is invalid, expired, or already used")
var ErrEndpointCertificateChanged = errors.New("endpoint certificate is no longer current")
var ErrAssetNotFound = errors.New("asset not found")
var ErrInvalidAssetLifecycle = errors.New("invalid asset lifecycle status")
var ErrWorkerJobReplay = errors.New("scanner-worker job identifier was already used")
var ErrWorkerResultReplay = errors.New("scanner-worker result identifier was already used")
var ErrInvalidWorkerJobLease = errors.New("scanner-worker job lease is invalid")
var ErrWorkerEvidenceReplay = errors.New("scanner-worker evidence batch was already accepted")
var ErrWorkerEvidenceSequence = errors.New("scanner-worker evidence batch sequence is invalid")
var ErrWorkerJobNotResumable = errors.New("scanner-worker job is not ready for safe reassignment")

type Repository interface {
	Save(model.Scan) error
	Get(string) (model.Scan, error)
	List() ([]model.Scan, error)
	ReconcileInterrupted() error
	ListAssets() ([]model.Asset, error)
	UpdateAssetMetadata(string, model.AssetMetadata, model.AuditEvent) error
	UpdateAssetLifecycle(string, model.AssetLifecycleUpdate, model.AuditEvent) error
	AssetAgingSettings() (model.AssetAgingSettings, error)
	UpdateAssetAgingSettings(model.AssetAgingSettings, model.AuditEvent) error
	MergeAssets(model.AssetMergeRequest, model.AuditEvent) error
	AssetDetail(string, time.Time) (model.AssetDetail, error)
	RecordAssetEvidence(model.AssetEvidence) error
	UpsertAssetGroup(model.AssetGroup, model.AuditEvent) error
	ListAssetGroups() ([]model.AssetGroup, error)
	AssetGroupMemberships(string) ([]string, error)
	AddAssetGroupMember(string, string, string, time.Time, model.AuditEvent) error
	RemoveAssetGroupMember(string, string, model.AuditEvent) error
	UpsertReusableScanPolicy(model.ReusableScanPolicy, model.AuditEvent) error
	ReusableScanPolicy(string) (model.ReusableScanPolicy, error)
	ListReusableScanPolicies(bool) ([]model.ReusableScanPolicy, error)
	ReusableScanPolicyTargets(string) ([]model.Target, error)
	UpdateReusablePolicySchedule(string, *time.Time, *time.Time, model.AuditEvent) error
	SMTPSettings() (model.SMTPSettings, error)
	SaveSMTPSettings(model.SMTPSettings, model.AuditEvent) error
	MarkScanLongAlertSent(string) error
	UpsertCVEs([]model.CVERecord) error
	MatchObservation(model.ServiceObservation) ([]model.CVEMatch, error)
	ListCriticalNews(int) ([]model.CVENewsItem, error)
	FeedStatus() (model.FeedStatus, error)
	RecordFeedStart(string, time.Time) error
	RecordFeedResult(string, time.Time, int, string) error
	IdentityInitialized() (bool, error)
	BootstrapAdministrator(model.User, string, model.BootstrapMFA, model.AuditEvent) error
	LocalIdentityByEmail(string) (model.LocalIdentity, error)
	LocalIdentityByID(string) (model.LocalIdentity, error)
	CreateSession(model.Session, model.AuditEvent) error
	SessionUser([]byte, time.Time) (model.User, error)
	DeleteSession([]byte, model.AuditEvent) error
	TOTPSecret(string) ([]byte, int64, error)
	ConsumeTOTPCounter(string, int64) (bool, error)
	ConsumeRecoveryCode(string, []byte, time.Time, model.AuditEvent) (bool, error)
	LoginThrottle([]byte, time.Time) (time.Time, bool, error)
	RecordLoginFailure([]byte, time.Time, time.Duration, int, time.Duration, time.Duration) (time.Time, error)
	ClearLoginFailures(...[]byte) error
	AppendAuditEvent(model.AuditEvent) error
	ListUserSessions(string, []byte, time.Time) ([]model.SessionInfo, error)
	RevokeUserSession(string, string, model.AuditEvent) error
	RevokeOtherUserSessions(string, []byte, model.AuditEvent) error
	CreateAuthenticationCeremony(model.AuthenticationCeremony) error
	ConsumeAuthenticationCeremony([]byte, model.AuthenticationCeremonyKind) (model.AuthenticationCeremony, error)
	SessionMFAVerifiedAt([]byte, string, time.Time) (*time.Time, error)
	UpdateSessionMFAVerifiedAt([]byte, string, time.Time) error
	DeleteWebAuthnCredential(string, []byte) (bool, error)
	UpdateWebAuthnCredential(model.WebAuthnCredential) error
	ListUsers() ([]model.User, error)
	UpdateUserAccess(string, model.UserRole, model.UserStatus, time.Time, model.AuditEvent) error
	CreateInvitation(model.Invitation, model.AuditEvent) error
	ListInvitations(time.Time) ([]model.Invitation, error)
	InvitationByTokenHash([]byte, time.Time) (model.Invitation, error)
	AcceptLocalInvitation(model.Invitation, model.User, string, model.BootstrapMFA, time.Time, model.AuditEvent) error
	UpsertOIDCProvider(model.OIDCProviderRecord, model.AuditEvent) error
	ListOIDCProviders() ([]model.OIDCProviderRecord, error)
	OIDCProvider(string) (model.OIDCProviderRecord, error)
	MarkOIDCProviderTested(string, time.Time, model.AuditEvent) error
	SetOIDCProviderEnabled(string, bool, time.Time, model.AuditEvent) error
	ResolveOIDCUser(model.OIDCProvider, model.OIDCClaims, model.UserRole, time.Time, model.AuditEvent) (model.User, error)
	AuthenticationPolicy() (model.AuthenticationPolicy, error)
	SaveAuthenticationPolicy(model.AuthenticationPolicy, time.Time, model.AuditEvent) error
	ListAuditEvents(model.AuditQuery) ([]model.AuditEvent, error)
	EnsureDefaultScopePolicy(model.ScopePolicy) error
	UpsertScopePolicy(model.ScopePolicy, model.AuditEvent) error
	ScopePolicy(string) (model.ScopePolicy, error)
	ListScopePolicies(bool) ([]model.ScopePolicy, error)
	CreateAgentEnrollmentToken(model.AgentEnrollmentToken, model.AuditEvent) error
	ListAgentEnrollmentTokens(time.Time) ([]model.AgentEnrollmentToken, error)
	AgentEnrollmentTokenName([]byte, time.Time) (string, error)
	ConsumeAgentEnrollmentToken([]byte, model.Endpoint, time.Time, model.AuditEvent) error
	ListEndpoints() ([]model.Endpoint, error)
	EndpointBySerial(string) (model.Endpoint, error)
	MarkEndpointSeen(string, time.Time) error
	RenewEndpointCertificate(string, model.Endpoint, model.AuditEvent) error
	RevokeEndpoint(string, string, time.Time, model.AuditEvent) error
	CreateWorkerEnrollmentToken(model.WorkerEnrollmentToken, model.AuditEvent) error
	WorkerEnrollmentToken([]byte, time.Time) (model.WorkerEnrollmentToken, error)
	ConsumeWorkerEnrollmentToken([]byte, model.ScannerWorker, time.Time, model.AuditEvent) error
	ListScannerWorkers() ([]model.ScannerWorker, error)
	ScannerWorkerBySerial(string) (model.ScannerWorker, error)
	RecordScannerWorkerHeartbeat(string, model.WorkerHeartbeat, time.Time) error
	RevokeScannerWorker(string, string, time.Time, model.AuditEvent) error
	ScannerWorkerDispatchSettings() (model.WorkerDispatchSettings, error)
	SetScannerWorkerDispatch(bool, model.AuditEvent) error
	SetScannerWorkerDispatchForWorker(string, bool, model.AuditEvent) error
	CreateScannerWorkerJob(model.SignedWorkerJob, time.Time) error
	ScannerWorkerJob(string) (model.SignedWorkerJob, error)
	LeaseScannerWorkerJob(string, []byte, time.Time, time.Time) (model.SignedWorkerJob, error)
	CompleteScannerWorkerJob(model.WorkerJobResultReceipt, []byte, time.Time) error
	RecordScannerWorkerEvidenceBatch(model.SignedWorkerEvidenceBatch, time.Time) error
	ScannerWorkerJobCheckpoints(string) ([]model.WorkerCheckpoint, error)
	ScannerWorkerJobLoads(time.Time) (map[string]model.WorkerJobLoad, error)
	ScannerWorkerJobResumeCandidate(string, time.Time) (model.WorkerJobResumeCandidate, error)
	ReassignScannerWorkerJob(string, model.SignedWorkerJob, time.Time) error
	Close() error
}
