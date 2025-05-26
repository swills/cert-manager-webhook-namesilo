package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	_ "time/tzdata"

	_ "github.com/breml/rootcerts"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/swills/cert-manager-webhook-namesilo/namesilo"
	"github.com/swills/cert-manager-webhook-namesilo/utils"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	// Email           string `json:"email"`
	// APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`

	APIKey cmmetav1.SecretKeySelector `json:"apiKey"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "namesilo"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(challengeRequest *v1alpha1.ChallengeRequest) error {
	var err error

	var cfg customDNSProviderConfig

	cfg, err = loadConfig(challengeRequest.Config)
	if err != nil {
		return err
	}

	var apiKey string

	apiKey, err = c.loadAPIKey(cfg, challengeRequest)
	if err != nil {
		return err
	}

	utils.Log("Presenting TXT record %s for %s, %s",
		challengeRequest.Key, challengeRequest.ResolvedFQDN, challengeRequest.ResolvedZone)

	// sets a record in the DNS provider's console
	var resp namesilo.Response

	resp, err = namesilo.Call[namesilo.Response](apiKey, "dnsAddRecord", map[string]string{
		"domain":  namesilo.GetDomainFromZone(challengeRequest.ResolvedZone),
		"rrtype":  "TXT",
		"rrhost":  strings.TrimSuffix(challengeRequest.ResolvedFQDN, "."+strings.ToLower(challengeRequest.ResolvedZone)),
		"rrvalue": challengeRequest.Key,
	})
	if err != nil {
		return err
	}

	if resp.Reply.Code != "300" {
		utils.Log("Error adding TXT record %s for %s, %s: %s",
			challengeRequest.Key, challengeRequest.ResolvedFQDN, challengeRequest.ResolvedZone, resp.Reply.Detail)

		return fmt.Errorf("error adding TXT record: %s, %w", resp.Reply.Detail, ErrTXTRecordCreate)
	}

	utils.Log("Added TXT record %s for %s, %s",
		challengeRequest.Key, challengeRequest.ResolvedFQDN, challengeRequest.ResolvedZone)

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(challengeRequest *v1alpha1.ChallengeRequest) error {
	var err error

	var cfg customDNSProviderConfig

	// add code that deletes a record from the DNS provider's console
	cfg, err = loadConfig(challengeRequest.Config)
	if err != nil {
		return err
	}

	var apiKey string

	apiKey, err = c.loadAPIKey(cfg, challengeRequest)
	if err != nil {
		return err
	}

	// 1. fetch the TXT record id
	var listResp namesilo.DNSRecordListResponse

	listResp, err = namesilo.Call[namesilo.DNSRecordListResponse](apiKey, "dnsListRecords", map[string]string{
		"domain": namesilo.GetDomainFromZone(challengeRequest.ResolvedZone),
	})
	if err != nil {
		utils.Log("Error listing TXT records for %s, %s: %s",
			challengeRequest.ResolvedFQDN, challengeRequest.ResolvedZone, err.Error())

		return err
	}

	if listResp.Reply.Code != "300" {
		return fmt.Errorf("error fetching txt record: %s, %w", listResp.Reply.Detail, ErrTXTRecordFetch)
	}

	var targetRecordID string

	for _, r := range listResp.Reply.ResourceRecord {
		if r.Host == namesilo.GetDomainFromZone(challengeRequest.ResolvedFQDN) &&
			r.Type == "TXT" && r.Value == challengeRequest.Key {
			targetRecordID = r.ResourceID

			break
		}
	}

	if targetRecordID == "" {
		utils.Log("No TXT record found for %s", challengeRequest.ResolvedFQDN)

		for _, r := range listResp.Reply.ResourceRecord {
			utils.Log("%s %s %s %s", r.ResourceID, r.Type, r.Host, r.Value)
		}

		return fmt.Errorf("no TXT record found for %s, %w", challengeRequest.ResolvedFQDN, ErrTXTRecordNotFound)
	}

	utils.Log("Found TXT record %s for %s, %s",
		targetRecordID, challengeRequest.ResolvedFQDN, challengeRequest.ResolvedZone)

	// 2. delete the TXT record
	var deleteResp namesilo.Response

	deleteResp, err = namesilo.Call[namesilo.Response](apiKey, "dnsDeleteRecord", map[string]string{
		"domain": namesilo.GetDomainFromZone(challengeRequest.ResolvedZone),
		"rrid":   targetRecordID,
	})
	if err != nil {
		return err
	}

	if deleteResp.Reply.Code != "300" {
		utils.Log("Error deleting TXT record %s for %s, %s: %s",
			targetRecordID, challengeRequest.ResolvedFQDN, challengeRequest.ResolvedZone, deleteResp.Reply.Detail)

		return fmt.Errorf("error deleting TXT record: %s, %w", deleteResp.Reply.Detail, ErrTXTRecordDelete)
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("error getting client config: %w", err)
	}

	c.client = cl

	return nil
}

// loadAPIKey loads namesilo API key
func (c *customDNSProviderSolver) loadAPIKey(cfg customDNSProviderConfig, challengeRequest *v1alpha1.ChallengeRequest) (string, error) { //nolint:lll
	backGroundCtx := context.Background()

	secret, err := c.client.CoreV1().Secrets(challengeRequest.ResourceNamespace).Get(
		backGroundCtx, cfg.APIKey.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting api key: %w", err)
	}

	keyBytes, ok := secret.Data[cfg.APIKey.Key]
	if !ok {
		return "", fmt.Errorf("secret key not found, namespace: %s name: %s, key: %s, got: %#v, %w",
			challengeRequest.ResourceNamespace, cfg.APIKey.Name, cfg.APIKey.Key, secret, ErrAPIKeyDecode)
	}

	return string(keyBytes), nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}

	err := json.Unmarshal(cfgJSON.Raw, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %w", err)
	}

	return cfg, nil
}
