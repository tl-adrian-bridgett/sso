package proxy

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/micro/go-micro/config"
	"github.com/micro/go-micro/config/source/env"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/xerrors"
)

// DefaultProxyCongig specifies all the defaults used to configure sso-proxy
// All configuration can be set using environment variables. Below is a list of
// configuration variables vai their environment configuraiton
//
// SESSION_COOKIE_NAME
// SESSION_COOKIE_SECRET
// SESSION_COOKIE_EXPIRE
// SESSION_COOKIE_DOMAIN
// SESSION_COOKIE_HTTPONLY
// SESSION_TTL_LIFETIME
// SESSION_TTL_VALID
// SESSION_TTL_GRACEPERIOD
//
// REQUESTSIGNER_KEY
//
// CLIENT_ID
// CLIENT_SECRET
//
// SERVER_PORT
// SERVER_CLUSTER
// SERVER_SCHEME
// SERVER_TIMEOUT_SHUTDOWN
// SERVER_TIMEOUT_READ
// SERVER_TIMEOUT_WRITE
//
// METRICS_STATSD_HOST
// METRICS_STATSD_PORT
//
// LOGGING_ENABLE
// LOGGING_LEVEL
//
// UPSTREAM_DEFAULT_EMAIL_DOMAINS
// UPSTREAM_DEFAULT_EMAIL_ADDRESSES
// UPSTREAM_DEFAULT_EMAIL_GROUPS
// UPSTREAM_DEFAULT_TIMEOUT
// UPSTREAM_DEFAULT_TCP_RESET_DEADLINE
// UPSTREAM_DEFAULT_PROVIDER_SLUG
// UPSTREAM_CONFIGS_FILE
//
// PROVIDER_TYPE
// PROVIDER_URL_EXTERNAL
// PROVIDER_URL_INTERNAL
// PROVIDER_SLUG
// PROVIDER_SCOPE

func DefaultProxyConfig() Configuration {
	return Configuration{
		ServerConfig: ServerConfig{
			Scheme: "https",
			Port:   4180,
			TimeoutConfig: TimeoutConfig{
				Write:    30 * time.Second,
				Read:     30 * time.Second,
				Shutdown: 30 * time.Second,
			},
		},
		ProviderConfig: ProviderConfig{
			ProviderType: "sso",
			ProviderSlug: "google",
		},
		SessionConfig: SessionConfig{
			CookieConfig: CookieConfig{
				Name:     "_sso_proxy",
				Expire:   168 * time.Hour,
				Secure:   true,
				HTTPOnly: true,
			},
			TTLConfig: TTLConfig{
				Lifetime:    720 * time.Hour,
				Valid:       60 * time.Second,
				GracePeriod: 3 * time.Hour,
			},
		},
		UpstreamConfigs: UpstreamConfigs{
			DefaultConfig: DefaultConfig{
				Timeout:       10 * time.Second,
				ResetDeadline: 60 * time.Second,
			},
		},
		LoggingConfig: LoggingConfig{
			Enable: true,
			Level:  "INFO",
		},
	}
}

type Validator interface {
	Validate() error
}

var (
	_ Validator = Configuration{}
	_ Validator = ProviderConfig{}
	_ Validator = SessionConfig{}
	_ Validator = CookieConfig{}
	_ Validator = TTLConfig{}
	_ Validator = ClientConfig{}
	_ Validator = ServerConfig{}
	_ Validator = TimeoutConfig{}
	_ Validator = MetricsConfig{}
	_ Validator = StatsdConfig{}
	_ Validator = LoggingConfig{}
	_ Validator = UpstreamConfigs{}
	_ Validator = DefaultConfig{}
	_ Validator = EmailConfig{}
	_ Validator = RequestSignerConfig{}
)

type Configuration struct {
	ServerConfig        ServerConfig        `mapstructure:"server"`
	ProviderConfig      ProviderConfig      `mapstructure:"provider"`
	ClientConfig        ClientConfig        `mapstructure:"client"`
	SessionConfig       SessionConfig       `mapstructure:"session"`
	UpstreamConfigs     UpstreamConfigs     `mapstructure:"upstream"`
	MetricsConfig       MetricsConfig       `mapstructrue:"metrics"`
	LoggingConfig       LoggingConfig       `mapstructure:"logging"`
	RequestSignerConfig RequestSignerConfig `mapstructure:"requestsigner"`
}

func (c Configuration) Validate() error {
	if err := c.ServerConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid server config: %w", err)
	}

	if err := c.ProviderConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid provider config: %w", err)
	}

	if err := c.SessionConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid session config: %w", err)
	}

	if err := c.ClientConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid session config: %w", err)
	}

	if err := c.UpstreamConfigs.Validate(); err != nil {
		return xerrors.Errorf("invalid upstream config: %w", err)
	}

	if err := c.MetricsConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid metrics config: %w", err)
	}

	if err := c.LoggingConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid metrics config: %w", err)
	}

	if err := c.RequestSignerConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid metrics config: %w", err)
	}

	return nil
}

type ProviderConfig struct {
	ProviderType              string `mapstructure:"type"`
	ProviderSlug              string `mapstructure:"slug"`
	Scope                     string `mapstructure:"scope"`
	ProviderURLExternal       string `mapstructure:"url_external"`
	ProviderURLInternal       string `mapstructure:"url_internal"`
	ProviderSkipAuthPreflight string `mapstructure:"skip_auth_preflight"`
}

func (pc ProviderConfig) Validate() error {
	if pc.ProviderType == "" {
		return xerrors.Errorf("invalid provider.type: %q", pc.ProviderType)
	}

	if pc.ProviderSlug == "" {
		return xerrors.Errorf("invalid provider.slug: %q", pc.ProviderSlug)
	}

	if pc.ProviderURLExternal == "" {
		return xerrors.Errorf("invalid provider.url_external: %q", pc.ProviderURLExternal)
	} else {
		providerURLExternal, err := url.Parse(pc.ProviderURLExternal)
		if err != nil {
			return err
		}
		if providerURLExternal.Scheme == "" || providerURLExternal.Host == "" {
			return errors.New("provider.url_external must include scheme and host")
		}
	}

	if pc.ProviderURLInternal == "" {
		return xerrors.Errorf("invalid provider.url_internal: %q", pc.ProviderURLInternal)
	} else {
		providerURLInternal, err := url.Parse(pc.ProviderURLInternal)
		if err != nil {
			return xerrors.Errorf("invalid pc.url_internal configured: %q", err)
		}
		if providerURLInternal.Scheme == "" || providerURLInternal.Host == "" {
			return errors.New("proxy provider url must include scheme and host")
		}
	}
	return nil
}

type SessionConfig struct {
	CookieConfig CookieConfig `mapstructure:"cookie"`
	TTLConfig    TTLConfig    `mapstructure:"ttl"`
}

func (sc SessionConfig) Validate() error {
	if err := sc.CookieConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid session.cookie config: %w", err)
	}

	if err := sc.TTLConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid session.ttl config: %w", err)
	}
	return nil
}

type CookieConfig struct {
	Name          string        `mapstructure:"name"`
	Secret        string        `mapstructure:"secret"`
	Expire        time.Duration `mapstructure:"expire"`
	Domain        string        `mapstructure:"domain"`
	Secure        bool          `mapstructure:"secure"`
	HTTPOnly      bool          `mapstructure:"httponly"`
	decodedSecret []byte
}

func (cc CookieConfig) Validate() error {
	if cc.Secret == "" {
		return xerrors.Errorf("no cookie.secret configured")
	}
	decodedCookieSecret, err := base64.StdEncoding.DecodeString(cc.Secret)
	if err != nil {
		return xerrors.Errorf("invalid cookie.secret configured; expected base64-encoded bytes, as from `openssl rand 32 -base64`: %q", err)
	}

	validCookieSecretLength := false
	for _, i := range []int{32, 64} {
		if len(decodedCookieSecret) == i {
			validCookieSecretLength = true
		}
	}
	if validCookieSecretLength {
		cc.decodedSecret = decodedCookieSecret
	} else {
		return xerrors.Errorf("Invalid value for cookie.secret; must decode to 32 or 64 bytes, but decoded to %d bytes", len(decodedCookieSecret))
	}

	cookie := &http.Cookie{Name: cc.Name}
	if cookie.String() == "" {
		//TODO: do we have to do this?
		return xerrors.Errorf("invalid cc.name: %q", cc.Name)
	}
	return nil
}

type TTLConfig struct {
	Lifetime    time.Duration `mapstructure:"lifetime"`
	Valid       time.Duration `mapstructure:"valid"`
	GracePeriod time.Duration `mapstructre:"grace_period"`
}

func (ttlc TTLConfig) Validate() error {
	return nil
}

type ClientConfig struct {
	ID     string `mapstructure:"id"`
	Secret string `mapstructure:"secret"`
}

func (cc ClientConfig) Validate() error {
	if cc.ID == "" {
		return xerrors.Errorf("no client.id configured")
	}
	if cc.Secret == "" {
		return xerrors.Errorf("no client.secret configured")
	}
	return nil
}

type ServerConfig struct {
	Port          int           `mapstructure:"port"`
	Cluster       string        `mapstructure:"cluster"`
	Scheme        string        `mapstructure:"scheme"`
	TimeoutConfig TimeoutConfig `mapstructure:"timeout"`
}

func (sc ServerConfig) Validate() error {
	if err := sc.TimeoutConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid server.timeout config: %w", err)
	}
	if sc.Cluster == "" {
		return xerrors.Errorf("no server.cluster configured")
	}
	return nil
}

type TimeoutConfig struct {
	Write    time.Duration `mapstructure:"write"`
	Read     time.Duration `mapstructure:"read"`
	Shutdown time.Duration `mapstructure:"shutdown"`
}

func (tc TimeoutConfig) Validate() error {
	return nil
}

type MetricsConfig struct {
	StatsdConfig StatsdConfig `mapstructure:"statsd"`
}

func (mc MetricsConfig) Validate() error {
	if err := mc.StatsdConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid metrics.statsd config: %w", err)
	}

	return nil
}

type StatsdConfig struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

func (sc StatsdConfig) Validate() error {
	if sc.Host == "" {
		return xerrors.New("no statsd.host configured")
	}

	if sc.Port == 0 {
		return xerrors.New(" no statsd.port configured")
	}

	return nil
}

type LoggingConfig struct {
	Enable bool   `mapstructure:"enable"`
	Level  string `mapstructure:"level"`
}

func (lc LoggingConfig) Validate() error {
	return nil
}

type UpstreamConfigs struct {
	DefaultConfig    DefaultConfig
	ConfigsFile      string `mapstructure:"config"`
	testTemplateVars map[string]string
	upstreamConfigs  []*UpstreamConfig
}

func (uc UpstreamConfigs) Validate() error {
	if uc.ConfigsFile != "" {
		r, err := os.Open(uc.ConfigsFile)
		if err != nil {
			return xerrors.Errorf("invalid upstream.config filepath: %w", err)
		}
		r.Close()
	}
	return nil
}

type DefaultConfig struct {
	EmailConfig   EmailConfig   `mapstructure:"email"`
	AllowedGroups []string      `mapstructure:"groups"`
	ProviderSlug  string        `mapstructure:"slug"`
	Timeout       time.Duration `mapstructure:"timeout"`
	ResetDeadline time.Duration `mapstructure:"resetdeadine"`
}

func (dc DefaultConfig) Validate() error {
	return nil
}

type EmailConfig struct {
	AllowedDomains   []string `mapstructure:"domains"`
	AllowedAddresses []string `mapstructure:"addresses"`
}

func (ec EmailConfig) Validate() error {
	return nil
}

type RequestSignerConfig struct {
	Key string `mapstructure:"key"`
}

func (rsc RequestSignerConfig) Validate() error {
	return nil
}

// LoadConfig loads all the configuration from env and defaults
func LoadConfig() (Configuration, error) {
	c := DefaultProxyConfig()

	conf := config.NewConfig()
	err := conf.Load(env.NewSource())
	if err != nil {
		return c, err
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
		Result: &c,
	})
	if err != nil {
		return c, err
	}

	err = decoder.Decode(conf.Map())
	if err != nil {
		return c, err
	}

	return c, nil
}
