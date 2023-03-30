package provider

import (
	"fmt"

	"github.com/PaloAltoNetworks/terraform-provider-prismacloudcompute/internal/api"
	"github.com/PaloAltoNetworks/terraform-provider-prismacloudcompute/internal/api/policy"
	"github.com/PaloAltoNetworks/terraform-provider-prismacloudcompute/internal/convert"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePoliciesRuntimeContainer() *schema.Resource {
	return &schema.Resource{
		Create: createPolicyRuntimeContainer,
		Read:   readPolicyRuntimeContainer,
		Update: updatePolicyRuntimeContainer,
		Delete: deletePolicyRuntimeContainer,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"id": {
				Description: "The ID of the policy.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"learning_disabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether or not to disable automatic behavioral learning.",
				Default:     false,
			},
			"rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Rules that make up the policy.",
				MinItems:    1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"advanced_protection": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
						},
						"cloud_metadata_enforcement": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The effect to be used. Can be set to 'block', 'alert', or 'disable'.",
						},
						"collections": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Collections used to scope the rule.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"custom_rule": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "List of custom rules.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"action": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The action to perform if the custom rule applies. Can be set to 'audit' or 'incident'.",
									},
									"effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'allow'.",
									},
									"id": {
										Type:        schema.TypeInt,
										Optional:    true,
										Description: "Custom rule number.",
									},
								},
							},
						},
						"disabled": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Whether or not to disable the rule.",
						},
						"dns": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Description: "DNS configuration.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"default_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', or 'alert'.",
									},
									"disabled": {
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "Whether or not to disable global DNS rule",
									},
									"domain_list": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of explicitly allowed/denied domains",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"allowed": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "Allowed domains. Wildcard prefixes are supported.",
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"denied": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "Denied domains. Wildcard prefixes are supported.",
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"effect": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
												},
											},
										},
									},
								},
							},
						},
						"filesystem": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Description: "File system configuration.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"allowed": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of allowed file system paths.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"backdoor_files_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
									},
									"default_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
									},
									"denied_list": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of denied file system paths.",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"effect": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "The effect to be used. Can be set to 'block', 'prevent', or alert'.",
												},
												"paths": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "Paths are the paths to alert/prevent/block when an event with one of the paths is triggered. Wildcard prefixes are supported.",
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
											},
										},
									},
									"disabled": {
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "Whether or not to disable the filesystem rule",
									},
									"encrypted_binaries_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
									},
									"new_files_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
									},
									"suspicious_elf_headers_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
									},
								},
							},
						},
						"kubernetes_enforcement_effect": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
						},
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Unique name of the rule.",
						},
						"network": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Description: "Network configuration.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"allowed_outbound_ips": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of allowed outbound IP addresses.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"default_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block' or 'alert'.",
									},
									"denied_outbound_ips": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of denied outbound IP addresses.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"denied_outbound_ips_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'alert', or 'disable'.",
									},
									"disabled": {
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "Whether or not to disable the network rule",
									},
									"listening_ports": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "Rule containing ports to allowed/denied and the required effect.",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"allowed": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "List of allowed listening ports.",
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"deny": {
																Type:        schema.TypeBool,
																Optional:    true,
																Description: "Whether or not to deny the connection.",
															},
															"end": {
																Type:        schema.TypeInt,
																Optional:    true,
																Description: "End of the port range.",
															},
															"start": {
																Type:        schema.TypeInt,
																Optional:    true,
																Description: "Start of the port range.",
															},
														},
													},
												},
												"denied": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "List of denied listening ports.",
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"deny": {
																Type:        schema.TypeBool,
																Optional:    true,
																Description: "Whether or not to deny the connection.",
															},
															"end": {
																Type:        schema.TypeInt,
																Optional:    true,
																Description: "End of the port range.",
															},
															"start": {
																Type:        schema.TypeInt,
																Optional:    true,
																Description: "Start of the port range.",
															},
														},
													},
												},
												"effect": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "The effect to be used. Can be set to 'block', 'alert', or 'disable'.",
												},
											},
										},
									},
									"modified_process_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'alert', or 'disable'.",
									},
									"outbound_ports": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "Rule containing ports to allowed/denied and the required effect.",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"allowed": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "List of allowed listening ports.",
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"deny": {
																Type:        schema.TypeBool,
																Optional:    true,
																Description: "Whether or not to deny the connection.",
															},
															"end": {
																Type:        schema.TypeInt,
																Optional:    true,
																Description: "End of the port range.",
															},
															"start": {
																Type:        schema.TypeInt,
																Optional:    true,
																Description: "Start of the port range.",
															},
														},
													},
												},
												"denied": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "List of denied listening ports.",
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"deny": {
																Type:        schema.TypeBool,
																Optional:    true,
																Description: "Whether or not to deny the connection.",
															},
															"end": {
																Type:        schema.TypeInt,
																Optional:    true,
																Description: "End of the port range.",
															},
															"start": {
																Type:        schema.TypeInt,
																Optional:    true,
																Description: "Start of the port range.",
															},
														},
													},
												},
												"effect": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "The effect to be used. Can be set to 'block', 'alert', or 'disable'.",
												},
											},
										},
									},
									"port_scan_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'alert', or 'disable'.",
									},
									"raw_sockets_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'alert' or 'disable'.",
									},
								},
							},
						},
						"notes": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Free-form text field.",
						},
						"processes": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Description: "Processes configuration.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"allowed": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of allowed processes.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"check_parent_child": {
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "Whether or not to check for parent-child relationship when comparing spawned processes in the model.",
									},
									"crypto_miners_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
									},
									"default_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'alert', 'prevent', or 'block'.",
									},
									"denied_list": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of denied processes and its effect to be used.",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"effect": {
													Type:        schema.TypeString,
													Optional:    true,
													Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
												},
												"paths": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "List of allowed processes.",
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
											},
										},
									},
									"disabled": {
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "Whether or not to disable the processes rule",
									},
									"lateral_movement_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'alert', or 'disable'.",
									},
									"modified_process_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
									},
									"reverse_shell_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'alert', or 'disable'.",
									},
									"suid_binaries_effect": {
										Type:        schema.TypeString,
										Optional:    true,
										Description: "The effect to be used. Can be set to 'block', 'prevent', 'alert', or 'disable'.",
									},
								},
							},
						},
						"wildfire_analysis": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The effect to be used when WildFire analysis is enabled. Can be set to 'block', 'alert', or 'disable'.",
						},
					},
				},
			},
		},
	}
}

func createPolicyRuntimeContainer(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	parsedRules, err := convert.SchemaToRuntimeContainerRules(d)
	if err != nil {
		return fmt.Errorf("error creating %s policy: %s", policyTypeRuntimeContainer, err)
	}

	parsedPolicy := policy.RuntimeContainerPolicy{
		Rules: parsedRules,
	}

	if err := policy.UpdateRuntimeContainer(*client, parsedPolicy); err != nil {
		return fmt.Errorf("error creating %s policy: %s", policyTypeRuntimeContainer, err)
	}

	d.SetId(policyTypeRuntimeContainer)
	return readPolicyRuntimeContainer(d, meta)
}

func readPolicyRuntimeContainer(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	retrievedPolicy, err := policy.GetRuntimeContainer(*client)
	if err != nil {
		return fmt.Errorf("error reading %s policy: %s", policyTypeRuntimeContainer, err)
	}

	d.Set("learning_disabled", retrievedPolicy.LearningDisabled)
	if err := d.Set("rule", convert.RuntimeContainerRulesToSchema(retrievedPolicy.Rules)); err != nil {
		return fmt.Errorf("error reading %s policy: %s", policyTypeRuntimeContainer, err)
	}
	return nil
}

func updatePolicyRuntimeContainer(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	parsedRules, err := convert.SchemaToRuntimeContainerRules(d)
	if err != nil {
		return fmt.Errorf("error updating %s policy: %s", policyTypeRuntimeContainer, err)
	}

	parsedPolicy := policy.RuntimeContainerPolicy{
		Rules: parsedRules,
	}

	if err := policy.UpdateRuntimeContainer(*client, parsedPolicy); err != nil {
		return fmt.Errorf("error updating %s policy: %s", policyTypeRuntimeContainer, err)
	}

	return readPolicyRuntimeContainer(d, meta)
}

func deletePolicyRuntimeContainer(d *schema.ResourceData, meta interface{}) error {
	// TODO: reset to default policy
	return nil
}
