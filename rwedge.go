package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	railwayGraphQLEndpoint     = "https://backboard.railway.com/graphql/v2"
	defaultRWReqTimeout        = 15 * time.Second
	defaultRWCertPollTick      = 5 * time.Second
	defaultRWCertPollWait      = 75 * time.Second
	defaultRWTargetPort        = 8080
	defaultRWTargetVCPUs       = 2
	defaultRWTargetMemoryGB    = 1
	defaultRWBootstrapRegion   = "europe-west4-drams3a"
	bermudaIPv6BootstrapFlag   = "BERMUDA_IPV6_BOOTSTRAPPED"
	bermudaRegionBootstrapFlag = "BERMUDA_REGION_BOOTSTRAPPED"
)

type rwAuthHeaderMode int

const (
	rwAuthBearer rwAuthHeaderMode = iota
	rwAuthProjectToken
)

type rwGraphQLError struct {
	Message    string         `json:"message"`
	Path       []any          `json:"path,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

type rwGraphQLEnvelope[T any] struct {
	Data   T                `json:"data"`
	Errors []rwGraphQLError `json:"errors,omitempty"`
}

type rwAPIError struct {
	StatusCode int
	Errors     []rwGraphQLError
}

func (e *rwAPIError) Error() string {
	if len(e.Errors) > 0 {
		msgs := make([]string, 0, len(e.Errors))
		for _, err := range e.Errors {
			if strings.TrimSpace(err.Message) != "" {
				msgs = append(msgs, strings.TrimSpace(err.Message))
			}
		}
		if len(msgs) > 0 {
			return fmt.Sprintf("railway graphql error (HTTP %d): %s", e.StatusCode, strings.Join(msgs, "; "))
		}
	}
	return fmt.Sprintf("railway api error (HTTP %d)", e.StatusCode)
}

func (e *rwAPIError) IsAuthError() bool {
	if e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden {
		return true
	}
	for _, msg := range e.Errors {
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "not authorized") ||
			strings.Contains(lower, "unauthorized") ||
			strings.Contains(lower, "invalid token") ||
			strings.Contains(lower, "authentication") {
			return true
		}
	}
	return false
}

func (e *rwAPIError) IsPermissionOrPlan() bool {
	if e.IsAuthError() {
		return true
	}
	for _, msg := range e.Errors {
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "plan") ||
			strings.Contains(lower, "quota") ||
			strings.Contains(lower, "limit") ||
			strings.Contains(lower, "upgrade") ||
			strings.Contains(lower, "subscription") ||
			strings.Contains(lower, "permission") ||
			strings.Contains(lower, "forbidden") ||
			strings.Contains(lower, "not allowed") {
			return true
		}
	}
	return false
}

func (e *rwAPIError) IsSchemaFieldError() bool {
	for _, msg := range e.Errors {
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "cannot query field") ||
			strings.Contains(lower, "unknown argument") ||
			strings.Contains(lower, "unknown field") ||
			strings.Contains(lower, "is not defined by type") {
			return true
		}
	}
	return false
}

type RailwayCustomDomainInfo struct {
	ID                string
	Domain            string
	CNAMETarget       string
	CNAMEHostLabel    string
	VerificationToken string
	VerificationHost  string
	CertificateStatus string
	RecordsVerified   bool
}

func (info *RailwayCustomDomainInfo) IsCertificateValid() bool {
	if info == nil {
		return false
	}
	st := strings.ToUpper(strings.TrimSpace(info.CertificateStatus))
	if st == "CERTIFICATE_STATUS_TYPE_VALID" || st == "VALID" || st == "ACTIVE" || st == "ISSUED" {
		return true
	}
	return strings.Contains(st, "VALID") && !strings.Contains(st, "VALIDATING") && !strings.Contains(st, "INVALID")
}

type RailwayClient struct {
	Token         string
	ProjectID     string
	EnvironmentID string
	ServiceID     string
	DeploymentID  string
	TargetPort    int
	apiURL        string
	client        *http.Client

	mu            sync.RWMutex
	authMode      rwAuthHeaderMode
	authVerified  bool
	serviceDomain string
	customDomain  string
	onTopology    func(railwayDom, cfDom string)
}

func sanitizeRailwayToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{"RAILWAY_API_TOKEN", "RAILWAY_TOKEN", "BERMUDA_RAILWAY_TOKEN"} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.TrimSpace(s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func NewRailwayClient(token string) *RailwayClient {
	cleanTok := sanitizeRailwayToken(token)
	if cleanTok == "" {
		return nil
	}

	port := getEnvInt("PORT", defaultRWTargetPort)
	if port <= 0 {
		port = defaultRWTargetPort
	}

	rwDom, cfDom := resolveInfrastructureDomains()

	return &RailwayClient{
		Token:         cleanTok,
		ProjectID:     sanitizeExplicitCredential(getEnv("RAILWAY_PROJECT_ID", "")),
		EnvironmentID: sanitizeExplicitCredential(getEnv("RAILWAY_ENVIRONMENT_ID", "")),
		ServiceID:     sanitizeExplicitCredential(getEnv("RAILWAY_SERVICE_ID", "")),
		DeploymentID:  sanitizeExplicitCredential(getEnv("RAILWAY_DEPLOYMENT_ID", "")),
		TargetPort:    port,
		apiURL:        railwayGraphQLEndpoint,
		serviceDomain: rwDom,
		customDomain:  cfDom,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *RailwayClient) IsConfigured() bool {
	return c != nil && c.Token != ""
}

func (c *RailwayClient) HasServiceContext() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ProjectID != "" && c.EnvironmentID != "" && c.ServiceID != ""
}

func (c *RailwayClient) SetTopologyCallback(fn func(railwayDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *RailwayClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	rw := c.serviceDomain
	cf := c.customDomain
	c.mu.RUnlock()
	if fn != nil {
		fn(rw, cf)
	}
}

func (c *RailwayClient) GetServiceDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serviceDomain
}

func (c *RailwayClient) GetCustomDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.customDomain
}

func (c *RailwayClient) SetServiceDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if !isRailwayPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.serviceDomain == "" || isFullRailwayServiceDomain(clean) {
		c.serviceDomain = clean
	}
	c.mu.Unlock()
}

func (c *RailwayClient) SetCustomDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isRailwayManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.customDomain = clean
	c.mu.Unlock()
}

func (c *RailwayClient) endpoint() string {
	if c != nil && c.apiURL != "" {
		return c.apiURL
	}
	return railwayGraphQLEndpoint
}

type rwGraphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

func doRWRequest[T any](ctx context.Context, c *RailwayClient, query string, variables map[string]any) (T, error) {
	var zero T
	if !c.IsConfigured() {
		return zero, errors.New("railway client not configured (missing token)")
	}

	c.mu.RLock()
	mode := c.authMode
	verified := c.authVerified
	c.mu.RUnlock()

	res, err := executeRWGraphQL[T](ctx, c, mode, query, variables)
	if err == nil {
		if !verified {
			c.mu.Lock()
			c.authVerified = true
			c.mu.Unlock()
		}
		return res, nil
	}

	var apiErr *rwAPIError
	if !verified && errors.As(err, &apiErr) && apiErr.IsAuthError() {
		altMode := rwAuthProjectToken
		if mode == rwAuthProjectToken {
			altMode = rwAuthBearer
		}
		if altRes, altErr := executeRWGraphQL[T](ctx, c, altMode, query, variables); altErr == nil {
			c.mu.Lock()
			c.authMode = altMode
			c.authVerified = true
			c.mu.Unlock()
			return altRes, nil
		}
	}

	return zero, err
}

func executeRWGraphQL[T any](ctx context.Context, c *RailwayClient, mode rwAuthHeaderMode, query string, variables map[string]any) (T, error) {
	var zero T

	payloadBytes, err := json.Marshal(rwGraphQLRequest{
		Query:     query,
		Variables: variables,
	})
	if err != nil {
		return zero, fmt.Errorf("marshal graphql request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, defaultRWReqTimeout)
		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint(), bytes.NewReader(payloadBytes))
		if reqErr != nil {
			cancel()
			return zero, fmt.Errorf("build railway graphql request: %w", reqErr)
		}

		if mode == rwAuthProjectToken {
			req.Header.Set("Project-Access-Token", c.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "BERMUDA-Portal-CloudOrchestrator/4.0 (Go-Standard-Library)")

		resp, doErr := c.client.Do(req)
		if doErr != nil {
			cancel()
			lastErr = doErr
			break
		}

		rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		cancel()

		if readErr != nil {
			return zero, fmt.Errorf("read railway response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(1500 * time.Millisecond):
				continue
			}
		}

		var env rwGraphQLEnvelope[T]
		if err := json.Unmarshal(rawBytes, &env); err != nil {
			snippet := string(rawBytes)
			if len(snippet) > 256 {
				snippet = snippet[:256]
			}
			return zero, &rwAPIError{
				StatusCode: resp.StatusCode,
				Errors:     []rwGraphQLError{{Message: snippet}},
			}
		}

		if resp.StatusCode >= 400 || len(env.Errors) > 0 {
			return env.Data, &rwAPIError{
				StatusCode: resp.StatusCode,
				Errors:     env.Errors,
			}
		}

		return env.Data, nil
	}

	return zero, lastErr
}

type rwProjectTokenData struct {
	ProjectToken struct {
		ProjectID     string `json:"projectId"`
		EnvironmentID string `json:"environmentId"`
	} `json:"projectToken"`
}

type rwProjectTopologyData struct {
	Project struct {
		ID           string `json:"id"`
		Environments struct {
			Edges []struct {
				Node struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"environments"`
		Services struct {
			Edges []struct {
				Node struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"services"`
	} `json:"project"`
}

func (c *RailwayClient) ResolveRuntimeContext(ctx context.Context) error {
	if !c.IsConfigured() {
		return errors.New("railway client not configured")
	}
	if c.HasServiceContext() {
		return nil
	}

	c.mu.RLock()
	projID := c.ProjectID
	envID := c.EnvironmentID
	srvID := c.ServiceID
	c.mu.RUnlock()

	if projID == "" || envID == "" {
		const tokenQuery = `query { projectToken { projectId environmentId } }`
		if res, err := doRWRequest[rwProjectTokenData](ctx, c, tokenQuery, nil); err == nil {
			if projID == "" && res.ProjectToken.ProjectID != "" {
				projID = res.ProjectToken.ProjectID
			}
			if envID == "" && res.ProjectToken.EnvironmentID != "" {
				envID = res.ProjectToken.EnvironmentID
			}
		}
	}

	if projID != "" && (envID == "" || srvID == "") {
		const projQuery = `query project($id: String!) {
			project(id: $id) {
				id
				environments { edges { node { id name } } }
				services { edges { node { id name } } }
			}
		}`
		if res, err := doRWRequest[rwProjectTopologyData](ctx, c, projQuery, map[string]any{"id": projID}); err == nil {
			if envID == "" && len(res.Project.Environments.Edges) > 0 {
				envID = res.Project.Environments.Edges[0].Node.ID
				for _, edge := range res.Project.Environments.Edges {
					if strings.EqualFold(edge.Node.Name, "production") {
						envID = edge.Node.ID
						break
					}
				}
			}
			if srvID == "" && len(res.Project.Services.Edges) > 0 {
				srvID = res.Project.Services.Edges[0].Node.ID
			}
		}
	}

	c.mu.Lock()
	if c.ProjectID == "" {
		c.ProjectID = projID
	}
	if c.EnvironmentID == "" {
		c.EnvironmentID = envID
	}
	if c.ServiceID == "" {
		c.ServiceID = srvID
	}
	ready := c.ProjectID != "" && c.EnvironmentID != "" && c.ServiceID != ""
	c.mu.Unlock()

	if !ready {
		return errors.New("incomplete railway service context (missing project/environment/service IDs)")
	}
	return nil
}

type rwVariableUpsertData struct {
	VariableUpsert bool `json:"variableUpsert"`
}

func (c *RailwayClient) UpsertVariable(ctx context.Context, name, value string, skipDeploys bool) error {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return err
	}

	c.mu.RLock()
	projID := c.ProjectID
	envID := c.EnvironmentID
	srvID := c.ServiceID
	c.mu.RUnlock()

	const mutation = `mutation variableUpsert($input: VariableUpsertInput!) {
		variableUpsert(input: $input)
	}`

	input := map[string]any{
		"projectId":     projID,
		"environmentId": envID,
		"serviceId":     srvID,
		"name":          name,
		"value":         value,
		"skipDeploys":   skipDeploys,
	}

	_, err := doRWRequest[rwVariableUpsertData](ctx, c, mutation, map[string]any{"input": input})
	if err != nil {
		var apiErr *rwAPIError
		if skipDeploys && errors.As(err, &apiErr) && apiErr.IsSchemaFieldError() {
			delete(input, "skipDeploys")
			_, err = doRWRequest[rwVariableUpsertData](ctx, c, mutation, map[string]any{"input": input})
		}
	}
	return err
}

func (c *RailwayClient) PersistMasterKey(ctx context.Context, masterKey string) bool {
	if !c.IsConfigured() || strings.TrimSpace(masterKey) == "" {
		return false
	}
	if err := c.UpsertVariable(ctx, "BERMUDA_MASTER_KEY", strings.TrimSpace(masterKey), true); err != nil {
		var apiErr *rwAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Printf("[Railway] Note: Auto-persisting BERMUDA_MASTER_KEY skipped (token permission restriction)")
			return false
		}
		log.Printf("[Railway] Warning: Could not persist BERMUDA_MASTER_KEY to Railway Variables: %v", err)
		return false
	}
	log.Println("[Railway] ✓ BERMUDA_MASTER_KEY persisted to Railway Service Variables (skipDeploys=true)")
	return true
}

type rwDNSRecordStatus struct {
	Hostlabel     string `json:"hostlabel"`
	RequiredValue string `json:"requiredValue"`
	CurrentValue  string `json:"currentValue"`
	Status        string `json:"status"`
}

type rwCustomDomainStatus struct {
	CertificateStatus string              `json:"certificateStatus"`
	VerificationToken string              `json:"verificationToken,omitempty"`
	DNSRecords        []rwDNSRecordStatus `json:"dnsRecords"`
}

type rwServiceDomainNode struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	TargetPort *int   `json:"targetPort,omitempty"`
}

type rwCustomDomainNode struct {
	ID         string               `json:"id"`
	Domain     string               `json:"domain"`
	TargetPort *int                 `json:"targetPort,omitempty"`
	Status     rwCustomDomainStatus `json:"status"`
}

type rwDomainsData struct {
	Domains struct {
		ServiceDomains []rwServiceDomainNode `json:"serviceDomains"`
		CustomDomains  []rwCustomDomainNode  `json:"customDomains"`
	} `json:"domains"`
}

func (c *RailwayClient) fetchDomains(ctx context.Context) (rwDomainsData, error) {
	var zero rwDomainsData
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return zero, err
	}

	c.mu.RLock()
	vars := map[string]any{
		"projectId":     c.ProjectID,
		"environmentId": c.EnvironmentID,
		"serviceId":     c.ServiceID,
	}
	c.mu.RUnlock()

	const fullQuery = `query domains($projectId: String!, $environmentId: String!, $serviceId: String!) {
		domains(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId) {
			serviceDomains {
				id
				domain
				targetPort
			}
			customDomains {
				id
				domain
				targetPort
				status {
					certificateStatus
					verificationToken
					dnsRecords {
						hostlabel
						requiredValue
						currentValue
						status
					}
				}
			}
		}
	}`

	res, err := doRWRequest[rwDomainsData](ctx, c, fullQuery, vars)
	if err == nil {
		return res, nil
	}

	var apiErr *rwAPIError
	if errors.As(err, &apiErr) && apiErr.IsSchemaFieldError() {
		const compatQuery = `query domains($projectId: String!, $environmentId: String!, $serviceId: String!) {
			domains(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId) {
				serviceDomains {
					id
					domain
				}
				customDomains {
					id
					domain
					status {
						certificateStatus
						dnsRecords {
							hostlabel
							requiredValue
							currentValue
							status
						}
					}
				}
			}
		}`
		return doRWRequest[rwDomainsData](ctx, c, compatQuery, vars)
	}

	return zero, err
}

type rwServiceDomainCreateData struct {
	ServiceDomainCreate rwServiceDomainNode `json:"serviceDomainCreate"`
}

func (c *RailwayClient) EnsureServiceDomain(ctx context.Context) (string, error) {
	domData, err := c.fetchDomains(ctx)
	if err != nil {
		return c.GetServiceDomain(), err
	}

	for _, sd := range domData.Domains.ServiceDomains {
		clean := cleanHost(sd.Domain)
		if isRailwayPublicDomain(clean) {
			c.SetServiceDomain(clean)
			if sd.TargetPort != nil && *sd.TargetPort != 0 && *sd.TargetPort != c.TargetPort {
				c.updateServiceDomainPort(ctx, sd.ID, clean, c.TargetPort)
			}
			c.notifyTopology()
			log.Printf("[Railway] ✓ Service Domain Verified: %s (Port %d)", clean, c.TargetPort)
			return clean, nil
		}
	}

	c.mu.RLock()
	envID := c.EnvironmentID
	srvID := c.ServiceID
	targetPort := c.TargetPort
	c.mu.RUnlock()

	const createMutation = `mutation serviceDomainCreate($input: ServiceDomainCreateInput!) {
		serviceDomainCreate(input: $input) {
			id
			domain
		}
	}`

	inputWithPort := map[string]any{
		"environmentId": envID,
		"serviceId":     srvID,
		"targetPort":    targetPort,
	}

	created, err := doRWRequest[rwServiceDomainCreateData](ctx, c, createMutation, map[string]any{"input": inputWithPort})
	if err != nil {
		var apiErr *rwAPIError
		if errors.As(err, &apiErr) && apiErr.IsSchemaFieldError() {
			inputBasic := map[string]any{
				"environmentId": envID,
				"serviceId":     srvID,
			}
			created, err = doRWRequest[rwServiceDomainCreateData](ctx, c, createMutation, map[string]any{"input": inputBasic})
			if err == nil && created.ServiceDomainCreate.ID != "" {
				c.updateServiceDomainPort(ctx, created.ServiceDomainCreate.ID, created.ServiceDomainCreate.Domain, targetPort)
			}
		}
	}
	if err != nil {
		return c.GetServiceDomain(), fmt.Errorf("create service domain: %w", err)
	}

	clean := cleanHost(created.ServiceDomainCreate.Domain)
	if clean != "" {
		c.SetServiceDomain(clean)
		c.notifyTopology()
		log.Printf("[Railway] ✓ Auto-Provisioned Railway Service Domain: %s (Target Port %d)", clean, targetPort)
	}
	return clean, nil
}

func (c *RailwayClient) updateServiceDomainPort(ctx context.Context, domainID, domainName string, port int) {
	c.mu.RLock()
	envID := c.EnvironmentID
	srvID := c.ServiceID
	c.mu.RUnlock()

	const updateMutation = `mutation serviceDomainUpdate($input: ServiceDomainUpdateInput!) {
		serviceDomainUpdate(input: $input)
	}`

	input := map[string]any{
		"id":            domainID,
		"environmentId": envID,
		"serviceId":     srvID,
		"domain":        domainName,
		"targetPort":    port,
	}
	if _, err := doRWRequest[map[string]any](ctx, c, updateMutation, map[string]any{"input": input}); err == nil {
		log.Printf("[Railway] ✓ Updated Service Domain %s targetPort -> %d", domainName, port)
	}
}

func buildVerificationHost(hostLbl, targetDomain string) string {
	hostLbl = strings.Trim(strings.ToLower(strings.TrimSpace(hostLbl)), ".")
	targetDomain = cleanHost(targetDomain)
	if hostLbl == "" || hostLbl == "@" || hostLbl == "_railway-verify" {
		return "_railway-verify." + targetDomain
	}
	if hostLbl == targetDomain || strings.HasSuffix(hostLbl, "."+targetDomain) {
		return hostLbl
	}
	if strings.HasPrefix(hostLbl, "_railway-verify.") {
		subPrefix := strings.TrimPrefix(hostLbl, "_railway-verify.")
		if strings.HasPrefix(targetDomain, subPrefix+".") {
			return "_railway-verify." + targetDomain
		}
	}
	return hostLbl + "." + targetDomain
}

func extractCustomDomainInfo(node rwCustomDomainNode, fallbackServiceDomain string) *RailwayCustomDomainInfo {
	domain := cleanHost(node.Domain)
	info := &RailwayCustomDomainInfo{
		ID:                node.ID,
		Domain:            domain,
		CertificateStatus: strings.TrimSpace(node.Status.CertificateStatus),
		VerificationHost:  "_railway-verify." + domain,
	}

	rawVerify := strings.TrimSpace(node.Status.VerificationToken)
	if rawVerify != "" {
		if strings.HasPrefix(strings.ToLower(rawVerify), "railway-verify=") {
			info.VerificationToken = rawVerify
		} else {
			info.VerificationToken = "railway-verify=" + rawVerify
		}
	}

	allVerified := len(node.Status.DNSRecords) > 0
	for _, rec := range node.Status.DNSRecords {
		reqVal := strings.TrimSpace(rec.RequiredValue)
		hostLbl := strings.TrimSpace(rec.Hostlabel)
		recStatus := strings.ToUpper(strings.TrimSpace(rec.Status))

		if !strings.Contains(recStatus, "VERIFIED") && !strings.Contains(recStatus, "VALID") && recStatus != "OK" {
			allVerified = false
		}

		if strings.HasPrefix(strings.ToLower(hostLbl), "_railway-verify") || strings.HasPrefix(strings.ToLower(reqVal), "railway-verify=") {
			if reqVal != "" {
				if strings.HasPrefix(strings.ToLower(reqVal), "railway-verify=") {
					info.VerificationToken = reqVal
				} else {
					info.VerificationToken = "railway-verify=" + reqVal
				}
			}
			info.VerificationHost = buildVerificationHost(hostLbl, domain)
			continue
		}

		cleanTarget := cleanHost(reqVal)
		if cleanTarget != "" && (info.CNAMETarget == "" || isRailwayManagedDomain(cleanTarget)) {
			info.CNAMETarget = cleanTarget
			info.CNAMEHostLabel = hostLbl
		}
	}

	if info.CNAMETarget == "" && fallbackServiceDomain != "" {
		info.CNAMETarget = cleanHost(fallbackServiceDomain)
	}
	info.RecordsVerified = allVerified
	return info
}

type rwCustomDomainCreateData struct {
	CustomDomainCreate rwCustomDomainNode `json:"customDomainCreate"`
}

func (c *RailwayClient) EnsureCustomDomain(ctx context.Context, targetDomain string) (*RailwayCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" || isRailwayManagedDomain(cleanTarget) {
		return nil, errors.New("invalid or empty custom domain target")
	}

	domData, err := c.fetchDomains(ctx)
	if err != nil {
		return nil, err
	}

	for _, sd := range domData.Domains.ServiceDomains {
		if cleanSD := cleanHost(sd.Domain); isRailwayPublicDomain(cleanSD) {
			c.SetServiceDomain(cleanSD)
		}
	}

	for _, cd := range domData.Domains.CustomDomains {
		if cleanHost(cd.Domain) == cleanTarget {
			c.SetCustomDomain(cleanTarget)
			c.notifyTopology()
			info := extractCustomDomainInfo(cd, c.GetServiceDomain())
			log.Printf("[Railway] ✓ Custom Domain Already Registered: %s (ID: %s, CNAME Target: %s, CertStatus: %s)",
				cleanTarget, info.ID, info.CNAMETarget, info.CertificateStatus)
			return info, nil
		}
	}

	c.mu.RLock()
	projID := c.ProjectID
	envID := c.EnvironmentID
	srvID := c.ServiceID
	targetPort := c.TargetPort
	c.mu.RUnlock()

	const createFullMutation = `mutation customDomainCreate($input: CustomDomainCreateInput!) {
		customDomainCreate(input: $input) {
			id
			domain
			status {
				certificateStatus
				verificationToken
				dnsRecords {
					hostlabel
					requiredValue
					currentValue
					status
				}
			}
		}
	}`

	input := map[string]any{
		"projectId":     projID,
		"environmentId": envID,
		"serviceId":     srvID,
		"domain":        cleanTarget,
		"targetPort":    targetPort,
	}

	created, err := doRWRequest[rwCustomDomainCreateData](ctx, c, createFullMutation, map[string]any{"input": input})
	if err != nil {
		var apiErr *rwAPIError
		if errors.As(err, &apiErr) && apiErr.IsSchemaFieldError() {
			const createCompatMutation = `mutation customDomainCreate($input: CustomDomainCreateInput!) {
				customDomainCreate(input: $input) {
					id
					domain
					status {
						certificateStatus
						dnsRecords {
							hostlabel
							requiredValue
							currentValue
							status
						}
					}
				}
			}`
			created, err = doRWRequest[rwCustomDomainCreateData](ctx, c, createCompatMutation, map[string]any{"input": input})
		}
	}
	if err != nil {
		return nil, fmt.Errorf("register custom domain %s on railway: %w", cleanTarget, err)
	}

	c.SetCustomDomain(cleanTarget)
	c.notifyTopology()
	info := extractCustomDomainInfo(created.CustomDomainCreate, c.GetServiceDomain())

	for attempt := 0; attempt < 3 && (info.CNAMETarget == "" || len(created.CustomDomainCreate.Status.DNSRecords) == 0); attempt++ {
		select {
		case <-ctx.Done():
			break
		case <-time.After(1500 * time.Millisecond):
		}
		if refreshed, fetchErr := c.FetchCustomDomainStatus(ctx, info.ID, cleanTarget); fetchErr == nil && refreshed != nil && refreshed.CNAMETarget != "" {
			info = refreshed
			break
		}
	}

	log.Printf("[Railway] ✓ Auto-Registered Custom Domain on Port %d: %s -> CNAME Target: %s (CertStatus: %s)",
		targetPort, cleanTarget, info.CNAMETarget, info.CertificateStatus)
	return info, nil
}

type rwSingleCustomDomainData struct {
	CustomDomain rwCustomDomainNode `json:"customDomain"`
}

func (c *RailwayClient) FetchCustomDomainStatus(ctx context.Context, customDomainID, targetDomain string) (*RailwayCustomDomainInfo, error) {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return nil, err
	}

	if customDomainID != "" {
		c.mu.RLock()
		projID := c.ProjectID
		c.mu.RUnlock()

		const singleQuery = `query customDomain($id: String!, $projectId: String!) {
			customDomain(id: $id, projectId: $projectId) {
				id
				domain
				status {
					certificateStatus
					verificationToken
					dnsRecords {
						hostlabel
						requiredValue
						currentValue
						status
					}
				}
			}
		}`
		if res, err := doRWRequest[rwSingleCustomDomainData](ctx, c, singleQuery, map[string]any{
			"id":        customDomainID,
			"projectId": projID,
		}); err == nil && res.CustomDomain.ID != "" {
			return extractCustomDomainInfo(res.CustomDomain, c.GetServiceDomain()), nil
		}
	}

	domData, err := c.fetchDomains(ctx)
	if err != nil {
		return nil, err
	}
	cleanTarget := cleanHost(targetDomain)
	for _, cd := range domData.Domains.CustomDomains {
		if (customDomainID != "" && cd.ID == customDomainID) || (cleanTarget != "" && cleanHost(cd.Domain) == cleanTarget) {
			return extractCustomDomainInfo(cd, c.GetServiceDomain()), nil
		}
	}
	return nil, fmt.Errorf("custom domain %s not found on railway service", targetDomain)
}

func (c *RailwayClient) WaitCustomDomainCertificate(ctx context.Context, customDomainID, targetDomain string, maxWait time.Duration) (*RailwayCustomDomainInfo, bool) {
	if maxWait <= 0 {
		maxWait = defaultRWCertPollWait
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(defaultRWCertPollTick)
	defer ticker.Stop()

	var latest *RailwayCustomDomainInfo
	for {
		info, err := c.FetchCustomDomainStatus(waitCtx, customDomainID, targetDomain)
		if err == nil && info != nil {
			latest = info
			if info.IsCertificateValid() {
				log.Printf("[Railway] ✓ Custom Domain %s SSL Certificate ISSUED & VALID (%s)",
					info.Domain, info.CertificateStatus)
				return info, true
			}
		}

		select {
		case <-waitCtx.Done():
			return latest, false
		case <-ticker.C:
		}
	}
}

func probeKernelIPv6Route() bool {
	conn, err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func resolveRailwayRegionID(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case s == "":
		return defaultRWBootstrapRegion
	case strings.Contains(s, "europe") || strings.Contains(s, "amsterdam") || strings.Contains(s, "drams") || strings.Contains(s, "nl"):
		return "europe-west4-drams3a"
	case strings.Contains(s, "us-east") || strings.Contains(s, "virginia") || strings.Contains(s, "eqdc"):
		return "us-east4-eqdc4a"
	case strings.Contains(s, "us-west") || strings.Contains(s, "california") || strings.Contains(s, "oregon"):
		return "us-west2"
	case strings.Contains(s, "asia") || strings.Contains(s, "singapore") || strings.Contains(s, "eqsg"):
		return "asia-southeast1-eqsg3a"
	default:
		return raw
	}
}

func (c *RailwayClient) TuneComputeAndNetwork(ctx context.Context) {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		log.Printf("[Railway] Note: Compute & network auto-tuning skipped: %v", err)
		return
	}

	c.ensureComputeLimits(ctx)
	c.ensureDeployTopologyAndIPv6(ctx)
}

func (c *RailwayClient) ensureComputeLimits(ctx context.Context) {
	vCPUs := getEnvInt("BERMUDA_RAILWAY_VCPUS", defaultRWTargetVCPUs)
	memGB := getEnvInt("BERMUDA_RAILWAY_MEM_GB", defaultRWTargetMemoryGB)
	if vCPUs <= 0 || memGB <= 0 {
		return
	}

	c.mu.RLock()
	envID := c.EnvironmentID
	srvID := c.ServiceID
	c.mu.RUnlock()

	const limitsMutation = `mutation serviceInstanceLimitsUpdate($input: ServiceInstanceLimitsUpdateInput!) {
		serviceInstanceLimitsUpdate(input: $input)
	}`

	input := map[string]any{
		"environmentId": envID,
		"serviceId":     srvID,
		"vCPUs":         vCPUs,
		"memoryGB":      memGB,
	}

	if _, err := doRWRequest[map[string]any](ctx, c, limitsMutation, map[string]any{"input": input}); err != nil {
		var apiErr *rwAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Printf("[Railway] Note: Resource scaling (%d vCPU / %d GB RAM) skipped (plan quota or token scope restriction)", vCPUs, memGB)
			return
		}
		log.Printf("[Railway] Note: Resource limits update unapplied: %v", err)
		return
	}

	log.Printf("[Railway] ✓ Compute Scaling Enforced: %d vCPU / %d GB RAM", vCPUs, memGB)
}

type rwEnvironmentConfigData struct {
	Environment struct {
		ID     string         `json:"id"`
		Config map[string]any `json:"config"`
	} `json:"environment"`
}

func (c *RailwayClient) ensureDeployTopologyAndIPv6(ctx context.Context) {
	c.mu.RLock()
	envID := c.EnvironmentID
	srvID := c.ServiceID
	c.mu.RUnlock()

	ipv6KernelOnline := probeKernelIPv6Route()
	if ipv6KernelOnline {
		log.Println("[Railway] ✓ Outbound IPv6 Stack: ACTIVE & VERIFIED (Kernel IPv6 routing table online)")
	}

	ipv6Bootstrapped := strings.TrimSpace(getEnv(bermudaIPv6BootstrapFlag, "")) == "1"
	regionBootstrapped := strings.TrimSpace(getEnv(bermudaRegionBootstrapFlag, "")) == "1"

	targetRegion := resolveRailwayRegionID(getEnv("BERMUDA_DEFAULT_REGION", defaultRWBootstrapRegion))
	currentReplicaRegion := strings.ToLower(strings.TrimSpace(getEnv("RAILWAY_REPLICA_REGION", "")))

	if currentReplicaRegion == strings.ToLower(targetRegion) && !regionBootstrapped {
		_ = c.UpsertVariable(ctx, bermudaRegionBootstrapFlag, "1", true)
		regionBootstrapped = true
		log.Printf("[Railway] ✓ Service Region Verified: %s (Netherlands / Amsterdam)", targetRegion)
	}

	if (ipv6KernelOnline || ipv6Bootstrapped) && regionBootstrapped {
		return
	}

	const envQuery = `query environment($id: String!) {
		environment(id: $id) {
			id
			config
		}
	}`

	var existingRegions []string
	var configIPv6Enabled bool
	var configRegionAlreadySet bool

	envData, err := doRWRequest[rwEnvironmentConfigData](ctx, c, envQuery, map[string]any{"id": envID})
	if err == nil && envData.Environment.Config != nil {
		if svcs, ok := envData.Environment.Config["services"].(map[string]any); ok {
			if svcCfg, ok := svcs[srvID].(map[string]any); ok {
				if depCfg, ok := svcCfg["deploy"].(map[string]any); ok {
					if v6, ok := depCfg["ipv6EgressEnabled"].(bool); ok && v6 {
						configIPv6Enabled = true
					}
					if mrc, ok := depCfg["multiRegionConfig"].(map[string]any); ok {
						for regKey, val := range mrc {
							if val != nil {
								existingRegions = append(existingRegions, regKey)
								if strings.EqualFold(regKey, targetRegion) {
									configRegionAlreadySet = true
								}
							}
						}
					}
				}
			}
		}
	}

	needsIPv6Patch := !ipv6KernelOnline && !ipv6Bootstrapped && !configIPv6Enabled
	if configIPv6Enabled && !ipv6Bootstrapped {
		_ = c.UpsertVariable(ctx, bermudaIPv6BootstrapFlag, "1", true)
	}

	needsRegionPatch := !regionBootstrapped && (!configRegionAlreadySet || len(existingRegions) > 1)
	if configRegionAlreadySet && len(existingRegions) == 1 && !regionBootstrapped {
		_ = c.UpsertVariable(ctx, bermudaRegionBootstrapFlag, "1", true)
		log.Printf("[Railway] ✓ Default Region (%s) already active in EnvironmentConfig", targetRegion)
	}

	if !needsIPv6Patch && !needsRegionPatch {
		return
	}

	deployPatch := make(map[string]any)
	instanceInput := make(map[string]any)

	if needsIPv6Patch || configIPv6Enabled {
		deployPatch["ipv6EgressEnabled"] = true
		instanceInput["ipv6EgressEnabled"] = true
		_ = c.UpsertVariable(ctx, bermudaIPv6BootstrapFlag, "1", true)
	}

	if needsRegionPatch {
		regionMap := make(map[string]any)
		for _, oldReg := range existingRegions {
			if !strings.EqualFold(oldReg, targetRegion) {
				regionMap[oldReg] = nil
			}
		}
		regionMap[targetRegion] = map[string]any{
			"numReplicas": 1,
		}
		deployPatch["multiRegionConfig"] = regionMap
		instanceInput["multiRegionConfig"] = regionMap
		_ = c.UpsertVariable(ctx, bermudaRegionBootstrapFlag, "1", true)
	}

	const updateInstanceMutation = `mutation serviceInstanceUpdate($serviceId: String!, $environmentId: String!, $input: ServiceInstanceUpdateInput!) {
		serviceInstanceUpdate(serviceId: $serviceId, environmentId: $environmentId, input: $input)
	}`
	_, updateErr := doRWRequest[map[string]any](ctx, c, updateInstanceMutation, map[string]any{
		"serviceId":     srvID,
		"environmentId": envID,
		"input":         instanceInput,
	})

	const patchMutation = `mutation environmentPatchCommit($environmentId: String!, $patch: EnvironmentConfig!, $commitMessage: String) {
		environmentPatchCommit(environmentId: $environmentId, patch: $patch, commitMessage: $commitMessage)
	}`

	patch := map[string]any{
		"services": map[string]any{
			srvID: map[string]any{
				"deploy": deployPatch,
			},
		},
	}

	commitMsg := "BERMUDA PORTAL: Auto-Configure Default Region (Amsterdam) & Outbound IPv6"
	if _, patchErr := doRWRequest[map[string]any](ctx, c, patchMutation, map[string]any{
		"environmentId": envID,
		"patch":         patch,
		"commitMessage": commitMsg,
	}); patchErr == nil || updateErr == nil {
		if needsRegionPatch {
			log.Printf("[Railway] ✓ Default Region Bootstrapped -> %s (Manual dashboard region changes remain unlocked)", targetRegion)
		}
		if needsIPv6Patch {
			log.Println("[Railway] ✓ Outbound IPv6 (ipv6EgressEnabled=true) enforced via Railway API")
		}
		return
	}

	if needsIPv6Patch {
		log.Println("[Railway] Note: Outbound IPv6 is currently disabled on container; enable 'Outbound IPv6' in Railway Service Settings if Dual-Stack egress is desired.")
	}
}
