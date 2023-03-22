package policy

import (
	"fmt"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-prismacloudcompute/internal/api"
	"github.com/PaloAltoNetworks/terraform-provider-prismacloudcompute/internal/api/collection"
)

const RuntimeContainerEndpoint = "api/v1/policies/runtime/container"

type RuntimeContainerPolicy struct {
	LearningDisabled bool                   `json:"learningDisabled,omitempty"`
	Rules            []RuntimeContainerRule `json:"rules,omitempty"`
}

type RuntimeContainerRule struct {
	AdvancedProtectionEffect       string                       `json:"advancedProtectionEffect"`
	CloudMetadataEnforcementEffect string                       `json:"cloudMetadataEnforcementEffect"`
	Collections                    []collection.Collection      `json:"collections,omitempty"`
	CustomRules                    []RuntimeContainerCustomRule `json:"customRules,omitempty"`
	Disabled                       bool                         `json:"disabled"`
	Dns                            RuntimeContainerDns          `json:"dns,omitempty"`
	Filesystem                     RuntimeContainerFilesystem   `json:"filesystem,omitempty"`
	KubernetesEnforcementEffect    string                       `json:"kubernetesEnforcementEffect"`
	Name                           string                       `json:"name,omitempty"`
	Network                        RuntimeContainerNetwork      `json:"network,omitempty"`
	Notes                          string                       `json:"notes,omitempty"`
	Processes                      RuntimeContainerProcesses    `json:"processes,omitempty"`
	SkipExecSessions               bool                         `json:"skipExecSessions"`
	WildFireAnalysis               string                       `json:"wildFireAnalysis,omitempty"`
}

type RuntimeContainerCustomRule struct {
	Action string `json:"action,omitempty"`
	Effect string `json:"effect,omitempty"`
	Id     int    `json:"_id,omitempty"`
}

type RuntimeContainerDns struct {
	DefaultEffect string                       `json:"effect,omitempty"`
	Disabled      bool                         `json:"disabled"`
	DomainLists   []RuntimeContainerDomainList `json:"domainList,omitempty"`
}

type RuntimeContainerDomainList struct {
	Allowed []string `json:"allowed,omitempty"`
	Denied  []string `json:"denied,omitempty"`
	Effect  string   `json:"effect,omitempty"`
}

type RuntimeContainerFilesystem struct {
	Allowed                    []string                               `json:"allowedList,omitempty"`
	BackdoorFilesEffect        string                                 `json:"backdoorFiles,omitempty"`
	DefaultEffect              string                                 `json:"defaultEffect,omitempty"`
	DeniedList                 []RuntimeContainerFilesystemDeniedList `json:"deniedList,omitempty"`
	Disabled                   bool                                   `json:"disabled"`
	EncryptedBinariesEffect    string                                 `json:"encryptedBinariesEffect,omitempty"`
	NewFilesEffect             string                                 `json:"newFilesEffect,omitempty"`
	SuspiciousELFHeadersEffect string                                 `json:"suspiciousELFHeadersEffect,omitempty"`
}

type RuntimeContainerFilesystemDeniedList struct {
	Effect string   `json:"effect,omitempty"`
	Paths  []string `json:"paths,omitempty"`
}

type RuntimeContainerNetwork struct {
	AllowedIPs            []string                        `json:"allowedIPs,omitempty"`
	DefaultEffect         string                          `json:"defaultEffect,omitempty"`
	DeniedIPs             []string                        `json:"deniedIPs,omitempty"`
	DeniedIPsEffect       string                          `json:"deniedIPsEffect,omitempty"`
	Disabled              bool                            `json:"disabled"`
	ListeningPorts        []RuntimeContainerListeningPort `json:"listeningPorts,omitempty"`
	ModifiedProcessEffect string                          `json:"modifiedProcessEffect,omitempty"`
	OutboundPorts         []RuntimeContainerOutboundPort  `json:"outboundPorts,omitempty"`
	PortScanEffect        string                          `json:"portScanEffect,omitempty"`
	RawSocketEffect       string                          `json:"rawSocketEffect,omitempty"`
}

type RuntimeContainerListeningPort struct {
	Allow  []RuntimeContainerAllowedPort `json:"allow,omitempty"`
	Deny   []RuntimeContainerDeniedPort  `json:"deny,omitempty"`
	Effect string                        `json:"effect,omitempty"`
}

type RuntimeContainerOutboundPort struct {
	Allow  []RuntimeContainerAllowedPort `json:"allow,omitempty"`
	Deny   []RuntimeContainerDeniedPort  `json:"deny,omitempty"`
	Effect string                        `json:"effect,omitempty"`
}

type RuntimeContainerAllowedPort struct {
	Deny  bool `json:"deny"`
	End   int  `json:"end,omitempty"`
	Start int  `json:"start,omitempty"`
}

type RuntimeContainerDeniedPort struct {
	Deny  bool `json:"deny"`
	End   int  `json:"end,omitempty"`
	Start int  `json:"start,omitempty"`
}

type RuntimeContainerProcesses struct {
	AllowedList           []string                            `json:"allowedList,omitempty"`
	CheckParentChild      bool                                `json:"checkParentChild"`
	CryptoMinersEffect    string                              `json:"cryptoMinersEffect,omitempty"`
	DefaultEffect         string                              `json:"defaultEffect,omitempty"`
	DeniedList            []RuntimeContainerProcessDeniedList `json:"deniedList,omitempty"`
	Disabled              bool                                `json:"disabled"`
	LateralMovementEffect string                              `json:"lateralMovementEffect,omitempty"`
	ModifiedProcessEffect string                              `json:"modifiedProcessesEffect,omitempty"`
	ReverseShellEffect    string                              `json:"reverseShellEffect,omitempty"`
	SuidBinariesEffect    string                              `json:"suidBinariesEffect,omitempty"`
}

type RuntimeContainerProcessDeniedList struct {
	Effect string   `json:"effect,omitempty"`
	Paths  []string `json:"paths,omitempty"`
}

// Get the current container runtime policy.
func GetRuntimeContainer(c api.Client) (RuntimeContainerPolicy, error) {
	var ans RuntimeContainerPolicy
	if err := c.Request(http.MethodGet, RuntimeContainerEndpoint, nil, nil, &ans); err != nil {
		return ans, fmt.Errorf("error getting container runtime policy: %s", err)
	}
	return ans, nil
}

// Update the current container runtime policy.
func UpdateRuntimeContainer(c api.Client, policy RuntimeContainerPolicy) error {
	return c.Request(http.MethodPut, RuntimeContainerEndpoint, nil, policy, nil)
}
