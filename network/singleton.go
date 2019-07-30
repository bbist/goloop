package network

import (
	"crypto/elliptic"
	"os"
	"time"

	"github.com/icon-project/goloop/common/errors"
)

const (
	AlreadyListenedError = errors.CodeNetwork + iota
	AlreadyClosedError
	AlreadyDialingError
	AlreadyRegisteredReactorError
	AlreadyRegisteredProtocolError
	NotRegisteredReactorError
	NotRegisteredProtocolError
	NotRegisteredRoleError
	NotAuthorizedError
	NotAvailableError
	NotStartedError
	QueueOverflowError
	DuplicatedPacketError
)

var (
	ErrAlreadyListened           = errors.NewBase(AlreadyListenedError, "AlreadyListened")
	ErrAlreadyClosed             = errors.NewBase(AlreadyClosedError, "AlreadyClosed")
	ErrAlreadyDialing            = errors.NewBase(AlreadyDialingError, "AlreadyDialing")
	ErrAlreadyRegisteredReactor  = errors.NewBase(AlreadyRegisteredReactorError, "AlreadyRegisteredReactor")
	ErrAlreadyRegisteredProtocol = errors.NewBase(AlreadyRegisteredProtocolError, "AlreadyRegisteredProtocol")
	ErrNotRegisteredReactor      = errors.NewBase(NotRegisteredReactorError, "NotRegisteredReactor")
	ErrNotRegisteredProtocol     = errors.NewBase(NotRegisteredProtocolError, "NotRegisteredProtocol")
	ErrNotRegisteredRole         = errors.NewBase(NotRegisteredRoleError, "NotRegisteredRole")
	ErrNotAuthorized             = errors.NewBase(NotAuthorizedError, "NotAuthorized")
	ErrNotAvailable              = errors.NewBase(NotAvailableError, "NotAvailable")
	ErrNotStarted                = errors.NewBase(NotStartedError, "NotStarted")
	ErrQueueOverflow             = errors.NewBase(QueueOverflowError, "QueueOverflow")
	ErrDuplicatedPacket          = errors.NewBase(DuplicatedPacketError, "DuplicatedPacket")
	ErrIllegalArgument           = errors.ErrIllegalArgument
)

var (
	ExcludeLoggers = []string{
		"Listener",
		"Dialer",
		"PeerDispatcher",
		"Authenticator",
		"ChannelNegotiator",
		//"PeerToPeer",
		"ProtocolHandler",
		"NetworkManager",
	}
)

const (
	DefaultTransportNet         = "tcp4"
	DefaultDialTimeout          = 5 * time.Second
	DefaultReceiveQueueSize     = 1000
	DefaultPacketBufferSize     = 4096 //bufio.defaultBufSize=4096
	DefaultPacketPayloadMax     = 1024 * 1024
	DefaultPacketPoolNumBucket  = 20
	DefaultPacketPoolBucketLen  = 500
	DefaultDiscoveryPeriod      = 2 * time.Second
	DefaultSeedPeriod           = 3 * time.Second
	DefaultMinSeed              = 1
	DefaultAlternateSendPeriod  = 1 * time.Second
	DefaultSendTimeout          = 5 * time.Second
	DefaultSendQueueMaxPriority = 7
	DefaultSendQueueSize        = 1000
	DefaultEventQueueSize       = 100
	DefaultFailureQueueSize     = 100
	DefaultPeerSendQueueSize    = 1000
	DefaultPeerPoolExpireSecond = 5
	DefaultUncleLimit           = 1
	DefaultChildrenLimit        = 1
	DefaultNephewLimit          = 1
	DefaultPacketRewriteLimit   = 10
	DefaultPacketRewriteDelay   = 100 * time.Millisecond
	DefaultRttAccuracy          = 10 * time.Millisecond
	DefaultFailureNodeMin       = 2
	DefaultSelectiveFloodingAdd = 1
	DefaultSimplePeerIDSize     = 4
	UsingSelectiveFlooding      = true
)

var (
	PROTO_CONTOL = protocolInfo(0x0000)
)

var (
	PROTO_AUTH_KEY_REQ     = protocolInfo(0x0100)
	PROTO_AUTH_KEY_RESP    = protocolInfo(0x0200)
	PROTO_AUTH_SIGN_REQ    = protocolInfo(0x0300)
	PROTO_AUTH_SIGN_RESP   = protocolInfo(0x0400)
	PROTO_CHAN_JOIN_REQ    = protocolInfo(0x0500)
	PROTO_CHAN_JOIN_RESP   = protocolInfo(0x0600)
	PROTO_P2P_QUERY        = protocolInfo(0x0700)
	PROTO_P2P_QUERY_RESULT = protocolInfo(0x0800)
	PROTO_P2P_CONN_REQ     = protocolInfo(0x0900)
	PROTO_P2P_CONN_RESP    = protocolInfo(0x0A00)
	PROTO_P2P_RTT_REQ      = protocolInfo(0x0B00)
	PROTO_P2P_RTT_RESP     = protocolInfo(0x0C00)
)

var (
	DefaultSecureEllipticCurve = elliptic.P256()
	DefaultSecureSuites        = []SecureSuite{
		SecureSuiteNone,
		SecureSuiteTls,
		SecureSuiteEcdhe,
	}
	DefaultSecureAeadSuites = []SecureAeadSuite{
		SecureAeadSuiteChaCha20Poly1305,
		SecureAeadSuiteAes128Gcm,
		SecureAeadSuiteAes256Gcm,
	}
	DefaultSecureKeyLogWriter = os.Stdout
)
