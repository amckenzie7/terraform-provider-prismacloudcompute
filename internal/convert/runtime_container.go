package convert

import (
	"github.com/PaloAltoNetworks/terraform-provider-prismacloudcompute/internal/api/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func SchemaToRuntimeContainerRules(d *schema.ResourceData) ([]policy.RuntimeContainerRule, error) {
	parsedRules := make([]policy.RuntimeContainerRule, 0)
	if rules, ok := d.GetOk("rule"); ok {
		presentRules := rules.([]interface{})
		for _, val := range presentRules {
			presentRule := val.(map[string]interface{})
			parsedRule := policy.RuntimeContainerRule{}

			parsedRule.AdvancedProtectionEffect = presentRule["advanced_protection"].(string)
			parsedRule.CloudMetadataEnforcementEffect = presentRule["cloud_metadata_enforcement"].(string)

			parsedRule.Collections = PolicySchemaToCollections(presentRule["collections"].([]interface{}))

			presentCustomRules := presentRule["custom_rule"].([]interface{})
			parsedCustomRules := make([]policy.RuntimeContainerCustomRule, 0, len(presentCustomRules))
			for _, val := range presentCustomRules {
				presentCustomRule := val.(map[string]interface{})
				parsedCustomRules = append(parsedCustomRules, policy.RuntimeContainerCustomRule{
					Action: presentCustomRule["action"].(string),
					Effect: presentCustomRule["effect"].(string),
					Id:     presentCustomRule["id"].(int),
				})
			}
			parsedRule.CustomRules = parsedCustomRules

			parsedRule.Disabled = presentRule["disabled"].(bool)

			if presentRule["dns"].([]interface{})[0] != nil {
				presentDns := presentRule["dns"].([]interface{})[0].(map[string]interface{})
				parsedRule.Dns = policy.RuntimeContainerDns{
					DefaultEffect: presentDns["default_effect"].(string),
					Disabled:      presentDns["disabled"].(bool),
					DomainLists:   schemaToRuntimeContainerDomainList(presentDns["domain_list"].([]interface{})),
				}
			} else {
				parsedRule.Dns = policy.RuntimeContainerDns{}
			}

			if presentRule["filesystem"].([]interface{})[0] != nil {
				presentFilesystem := presentRule["filesystem"].([]interface{})[0].(map[string]interface{})
				parsedRule.Filesystem = policy.RuntimeContainerFilesystem{
					Allowed:                    SchemaToStringSlice(presentFilesystem["allowed"].([]interface{})),
					BackdoorFilesEffect:        presentFilesystem["backdoor_files_effect"].(string),
					DefaultEffect:              presentFilesystem["default_effect"].(string),
					DeniedList:                 schemaToRuntimeContainerFilesystemDeniedList(presentFilesystem["denied_list"].([]interface{})),
					Disabled:                   presentFilesystem["disabled"].(bool),
					EncryptedBinariesEffect:    presentFilesystem["encrypted_binaries_effect"].(string),
					NewFilesEffect:             presentFilesystem["new_files_effect"].(string),
					SuspiciousELFHeadersEffect: presentFilesystem["suspicious_elf_headers_effect"].(string),
				}
			} else {
				parsedRule.Filesystem = policy.RuntimeContainerFilesystem{}
			}

			parsedRule.KubernetesEnforcementEffect = presentRule["kubernetes_enforcement"].(string)
			parsedRule.Name = presentRule["name"].(string)

			if presentRule["network"].([]interface{})[0] != nil {
				presentNetwork := presentRule["network"].([]interface{})[0].(map[string]interface{})
				parsedRule.Network = policy.RuntimeContainerNetwork{
					AllowedIPs:            SchemaToStringSlice(presentNetwork["allowed_outbound_ips"].([]interface{})),
					DefaultEffect:         presentNetwork["default_effect"].(string),
					DeniedIPs:             SchemaToStringSlice(presentNetwork["denied_outbound_ips"].([]interface{})),
					DeniedIPsEffect:       presentNetwork["default_effect"].(string),
					Disabled:              presentNetwork["disabled"].(bool),
					ListeningPorts:        schemaToRuntimeContainerListeningPorts(presentNetwork["listening_ports"].([]interface{})),
					ModifiedProcessEffect: presentNetwork["modified_process_effect"].(string),
					OutboundPorts:         schemaToRuntimeContainerOutboundPorts(presentNetwork["outbound_ports"].([]interface{})),
					PortScanEffect:        presentNetwork["port_scan_effect"].(string),
					RawSocketEffect:       presentNetwork["raw_socket_effect"].(string),
				}
			} else {
				parsedRule.Network = policy.RuntimeContainerNetwork{}
			}

			parsedRule.Notes = presentRule["notes"].(string)

			if presentRule["processes"].([]interface{})[0] != nil {
				presentProcesses := presentRule["processes"].([]interface{})[0].(map[string]interface{})
				parsedRule.Processes = policy.RuntimeContainerProcesses{
					AllowedList:           SchemaToStringSlice(presentProcesses["allowed"].([]interface{})),
					CheckParentChild:      presentProcesses["check_parent_child"].(bool),
					CryptoMinersEffect:    presentProcesses["crypto_miners_effect"].(string),
					DefaultEffect:         presentProcesses["default_effect"].(string),
					DeniedList:            schemaToRuntimeContainerProcessDeniedList(presentProcesses["denied_list"].([]interface{})),
					Disabled:              presentProcesses["disabled"].(bool),
					LateralMovementEffect: presentProcesses["lateral_movement_effect"].(string),
					ModifiedProcessEffect: presentProcesses["modified_process_effect"].(string),
					ReverseShellEffect:    presentProcesses["reverse_shell_effect"].(string),
					SuidBinariesEffect:    presentProcesses["suid_binaries_effect"].(string),
				}
			} else {
				parsedRule.Processes = policy.RuntimeContainerProcesses{}
			}

			parsedRule.WildFireAnalysis = presentRule["wildfire_analysis"].(string)

			parsedRules = append(parsedRules, parsedRule)
		}
	}
	return parsedRules, nil
}

func schemaToRuntimeContainerAllowedPorts(in []interface{}) []policy.RuntimeContainerAllowedPort {
	parsedPorts := make([]policy.RuntimeContainerAllowedPort, 0, len(in))
	for _, val := range in {
		presentPort := val.(map[string]interface{})
		parsedPorts = append(parsedPorts, policy.RuntimeContainerAllowedPort{
			Deny:  presentPort["deny"].(bool),
			End:   presentPort["end"].(int),
			Start: presentPort["start"].(int),
		})
	}
	return parsedPorts
}

func schemaToRuntimeContainerDeniedPorts(in []interface{}) []policy.RuntimeContainerDeniedPort {
	parsedPorts := make([]policy.RuntimeContainerDeniedPort, 0, len(in))
	for _, val := range in {
		presentPort := val.(map[string]interface{})
		parsedPorts = append(parsedPorts, policy.RuntimeContainerDeniedPort{
			Deny:  presentPort["deny"].(bool),
			End:   presentPort["end"].(int),
			Start: presentPort["start"].(int),
		})
	}
	return parsedPorts
}

func schemaToRuntimeContainerListeningPorts(in []interface{}) []policy.RuntimeContainerListeningPort {
	parsedPorts := make([]policy.RuntimeContainerListeningPort, 0, len(in))
	for _, val := range in {
		presentPort := val.(map[string]interface{})
		parsedPorts = append(parsedPorts, policy.RuntimeContainerListeningPort{
			Allow:  schemaToRuntimeContainerAllowedPorts(presentPort["allowed"].([]interface{})),
			Deny:   schemaToRuntimeContainerDeniedPorts(presentPort["denied"].([]interface{})),
			Effect: presentPort["effect"].(string),
		})
	}
	return parsedPorts
}

func schemaToRuntimeContainerOutboundPorts(in []interface{}) []policy.RuntimeContainerOutboundPort {
	parsedPorts := make([]policy.RuntimeContainerOutboundPort, 0, len(in))
	for _, val := range in {
		presentPort := val.(map[string]interface{})
		parsedPorts = append(parsedPorts, policy.RuntimeContainerOutboundPort{
			Allow:  schemaToRuntimeContainerAllowedPorts(presentPort["allowed"].([]interface{})),
			Deny:   schemaToRuntimeContainerDeniedPorts(presentPort["denied"].([]interface{})),
			Effect: presentPort["effect"].(string),
		})
	}
	return parsedPorts
}

func schemaToRuntimeContainerDomainList(in []interface{}) []policy.RuntimeContainerDomainList {
	parsedDomainLists := make([]policy.RuntimeContainerDomainList, 0, len(in))
	for _, val := range in {
		presentDomainList := val.(map[string]interface{})
		parsedDomainLists = append(parsedDomainLists, policy.RuntimeContainerDomainList{
			Allowed: SchemaToStringSlice(presentDomainList["allowed"].([]interface{})),
			Denied:  SchemaToStringSlice(presentDomainList["denied"].([]interface{})),
			Effect:  presentDomainList["effect"].(string),
		})
	}
	return parsedDomainLists
}

func schemaToRuntimeContainerFilesystemDeniedList(in []interface{}) []policy.RuntimeContainerFilesystemDeniedList {
	parsedDeniedLists := make([]policy.RuntimeContainerFilesystemDeniedList, 0, len(in))
	for _, val := range in {
		presentDeniedList := val.(map[string]interface{})
		parsedDeniedLists = append(parsedDeniedLists, policy.RuntimeContainerFilesystemDeniedList{
			Effect: presentDeniedList["effect"].(string),
			Paths:  SchemaToStringSlice(presentDeniedList["paths"].([]interface{})),
		})
	}
	return parsedDeniedLists
}

func schemaToRuntimeContainerProcessDeniedList(in []interface{}) []policy.RuntimeContainerProcessDeniedList {
	parsedDeniedLists := make([]policy.RuntimeContainerProcessDeniedList, 0, len(in))
	for _, val := range in {
		presentDeniedList := val.(map[string]interface{})
		parsedDeniedLists = append(parsedDeniedLists, policy.RuntimeContainerProcessDeniedList{
			Effect: presentDeniedList["effect"].(string),
			Paths:  SchemaToStringSlice(presentDeniedList["paths"].([]interface{})),
		})
	}
	return parsedDeniedLists
}

func RuntimeContainerRulesToSchema(in []policy.RuntimeContainerRule) []interface{} {
	ans := make([]interface{}, 0, len(in))
	for _, val := range in {
		m := make(map[string]interface{})
		m["advanced_protection"] = val.AdvancedProtectionEffect
		m["cloud_metadata_enforcement"] = val.CloudMetadataEnforcementEffect
		m["collections"] = CollectionsToPolicySchema(val.Collections)
		m["custom_rule"] = runtimeContainerCustomRulesToSchema(val.CustomRules)
		m["disabled"] = val.Disabled
		m["dns"] = runtimeContainerDnsToSchema(val.Dns)
		m["filesystem"] = runtimeContainerFileystemToSchema(val.Filesystem)
		m["kubernetes_enforcement"] = val.KubernetesEnforcementEffect
		m["name"] = val.Name
		m["network"] = runtimeContainerNetworkToSchema(val.Network)
		m["notes"] = val.Notes
		m["processes"] = runtimeContainerProcessesToSchema(val.Processes)
		m["wildfire_analysis"] = val.WildFireAnalysis
		ans = append(ans, m)
	}
	return ans
}

func runtimeContainerCustomRulesToSchema(in []policy.RuntimeContainerCustomRule) []interface{} {
	ans := make([]interface{}, 0, len(in))
	for _, val := range in {
		m := make(map[string]interface{})
		m["action"] = val.Action
		m["effect"] = val.Effect
		m["id"] = val.Id
		ans = append(ans, m)
	}
	return ans
}

func runtimeContainerDnsToSchema(in policy.RuntimeContainerDns) []interface{} {
	ans := make([]interface{}, 0, 1)
	m := make(map[string]interface{})
	m["default_effect"] = in.DefaultEffect
	m["disabled"] = in.Disabled
	m["domain_list"] = runtimeContainerDomainListToSchema(in.DomainLists)
	ans = append(ans, m)
	return ans
}

func runtimeContainerDomainListToSchema(in []policy.RuntimeContainerDomainList) []interface{} {
	ans := make([]interface{}, 0, len(in))
	for _, val := range in {
		m := make(map[string]interface{})
		m["allowed"] = val.Allowed
		m["denied"] = val.Denied
		m["deny_effect"] = val.Effect
		ans = append(ans, m)
	}
	return ans
}

func runtimeContainerFileystemToSchema(in policy.RuntimeContainerFilesystem) []interface{} {
	ans := make([]interface{}, 0, 1)
	m := make(map[string]interface{})
	m["allowed"] = in.Allowed
	m["backdoor_files_effect"] = in.BackdoorFilesEffect
	m["default_effect"] = in.DefaultEffect
	m["denied_list"] = in.DeniedList
	m["disabled"] = in.Disabled
	m["encrypted_binaries_effect"] = in.EncryptedBinariesEffect
	m["new_files_effect"] = in.NewFilesEffect
	m["suspicious_elf_headers_effect"] = in.SuspiciousELFHeadersEffect
	ans = append(ans, m)
	return ans
}

func runtimeContainerNetworkToSchema(in policy.RuntimeContainerNetwork) []interface{} {
	ans := make([]interface{}, 0, 1)
	m := make(map[string]interface{})
	m["allowed_outbound_ips"] = in.AllowedIPs
	m["default_effect"] = in.DefaultEffect
	m["denied_outbound_ips"] = in.DeniedIPs
	m["denied_outbound_ips_effect"] = in.DeniedIPsEffect
	m["disabled"] = in.Disabled
	m["listening_ports"] = runtimeContainerListeningPortsToSchema(in.ListeningPorts)
	m["modified_process_effect"] = in.ModifiedProcessEffect
	m["outbound_ports"] = runtimeContainerOutboundPortsToSchema(in.OutboundPorts)
	m["port_scan_effect"] = in.PortScanEffect
	m["raw_sockets_effect"] = in.RawSocketEffect
	ans = append(ans, m)
	return ans
}

func runtimeContainerAllowedPortsToSchema(in []policy.RuntimeContainerAllowedPort) []interface{} {
	ans := make([]interface{}, 0, len(in))
	for _, val := range in {
		m := make(map[string]interface{})
		m["deny"] = val.Deny
		m["end"] = val.End
		m["start"] = val.Start
		ans = append(ans, m)
	}
	return ans
}

func runtimeContainerDeniedPortsToSchema(in []policy.RuntimeContainerDeniedPort) []interface{} {
	ans := make([]interface{}, 0, len(in))
	for _, val := range in {
		m := make(map[string]interface{})
		m["deny"] = val.Deny
		m["end"] = val.End
		m["start"] = val.Start
		ans = append(ans, m)
	}
	return ans
}

func runtimeContainerListeningPortsToSchema(in []policy.RuntimeContainerListeningPort) []interface{} {
	ans := make([]interface{}, 0, len(in))
	for _, val := range in {
		m := make(map[string]interface{})
		m["allowed"] = runtimeContainerAllowedPortsToSchema(val.Allow)
		m["denied"] = runtimeContainerDeniedPortsToSchema(val.Deny)
		m["effect"] = val.Effect
		ans = append(ans, m)
	}
	return ans
}

func runtimeContainerOutboundPortsToSchema(in []policy.RuntimeContainerOutboundPort) []interface{} {
	ans := make([]interface{}, 0, len(in))
	for _, val := range in {
		m := make(map[string]interface{})
		m["allowed"] = runtimeContainerAllowedPortsToSchema(val.Allow)
		m["denied"] = runtimeContainerDeniedPortsToSchema(val.Deny)
		m["effect"] = val.Effect
		ans = append(ans, m)
	}
	return ans
}

func runtimeContainerProcessesToSchema(in policy.RuntimeContainerProcesses) []interface{} {
	ans := make([]interface{}, 0, 1)
	m := make(map[string]interface{})
	m["allowed"] = in.AllowedList
	m["check_parent_child"] = in.CheckParentChild
	m["crypto_miners_effect"] = in.CryptoMinersEffect
	m["default_effect"] = in.DefaultEffect
	m["denied_list"] = in.DeniedList
	m["disabled"] = in.Disabled
	m["lateral_movement_effect"] = in.LateralMovementEffect
	m["modified_process_effect"] = in.ModifiedProcessEffect
	m["reverse_shell_effect"] = in.ReverseShellEffect
	m["suid_binaries_effect"] = in.SuidBinariesEffect
	ans = append(ans, m)
	return ans
}
