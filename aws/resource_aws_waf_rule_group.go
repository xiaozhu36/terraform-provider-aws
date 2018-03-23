package aws

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceAwsWafRuleGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsWafRuleGroupCreate,
		Read:   resourceAwsWafRuleGroupRead,
		Update: resourceAwsWafRuleGroupUpdate,
		Delete: resourceAwsWafRuleGroupDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"metric_name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validateWafMetricName,
			},
			"activated_rule": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"action": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"type": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"override_action": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"type": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"priority": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"rule_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"type": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  waf.WafRuleTypeRegular,
						},
					},
				},
			},
		},
	}
}

func resourceAwsWafRuleGroupCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).wafconn

	wr := newWafRetryer(conn, "global")
	out, err := wr.RetryWithToken(func(token *string) (interface{}, error) {
		params := &waf.CreateRuleGroupInput{
			ChangeToken: token,
			MetricName:  aws.String(d.Get("metric_name").(string)),
			Name:        aws.String(d.Get("name").(string)),
		}

		return conn.CreateRuleGroup(params)
	})
	if err != nil {
		return err
	}
	resp := out.(*waf.CreateRuleGroupOutput)
	d.SetId(*resp.RuleGroup.RuleGroupId)
	return resourceAwsWafRuleGroupUpdate(d, meta)
}

func resourceAwsWafRuleGroupRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).wafconn

	params := &waf.GetRuleGroupInput{
		RuleGroupId: aws.String(d.Id()),
	}

	resp, err := conn.GetRuleGroup(params)
	if err != nil {
		if isAWSErr(err, "WAFNonexistentItemException", "") {
			log.Printf("[WARN] WAF Rule Group (%s) not found, removing from state", d.Id())
			d.SetId("")
			return nil
		}

		return err
	}

	rResp, err := conn.ListActivatedRulesInRuleGroup(&waf.ListActivatedRulesInRuleGroupInput{
		RuleGroupId: aws.String(d.Id()),
	})

	d.Set("activated_rule", flattenWafActivatedRules(rResp.ActivatedRules))
	d.Set("name", resp.RuleGroup.Name)
	d.Set("metric_name", resp.RuleGroup.MetricName)

	return nil
}

func resourceAwsWafRuleGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).wafconn

	if d.HasChange("activated_rule") {
		o, n := d.GetChange("activated_rule")
		oldRules, newRules := o.(*schema.Set).List(), n.(*schema.Set).List()

		err := updateWafRuleGroupResource(d.Id(), oldRules, newRules, conn)
		if err != nil {
			return fmt.Errorf("Error Updating WAF Rule Group: %s", err)
		}
	}

	return resourceAwsWafRuleGroupRead(d, meta)
}

func resourceAwsWafRuleGroupDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).wafconn

	oldRules := d.Get("activated_rule").(*schema.Set).List()
	err := deleteWafRuleGroup(d.Id(), oldRules, conn)
	if err != nil {
		return err
	}

	return nil
}

func deleteWafRuleGroup(id string, oldRules []interface{}, conn *waf.WAF) error {
	if len(oldRules) > 0 {
		noRules := []interface{}{}
		err := updateWafRuleGroupResource(id, oldRules, noRules, conn)
		if err != nil {
			return fmt.Errorf("Error updating WAF Rule Group Predicates: %s", err)
		}
	}

	wr := newWafRetryer(conn, "global")
	_, err := wr.RetryWithToken(func(token *string) (interface{}, error) {
		req := &waf.DeleteRuleGroupInput{
			ChangeToken: token,
			RuleGroupId: aws.String(id),
		}
		log.Printf("[INFO] Deleting WAF Rule Group")
		return conn.DeleteRuleGroup(req)
	})
	if err != nil {
		return fmt.Errorf("Error deleting WAF Rule Group: %s", err)
	}
	return nil
}

func updateWafRuleGroupResource(id string, oldRules, newRules []interface{}, conn *waf.WAF) error {
	wr := newWafRetryer(conn, "global")
	_, err := wr.RetryWithToken(func(token *string) (interface{}, error) {
		req := &waf.UpdateRuleGroupInput{
			ChangeToken: token,
			RuleGroupId: aws.String(id),
			Updates:     diffWafRuleGroupActivatedRules(oldRules, newRules),
		}

		return conn.UpdateRuleGroup(req)
	})
	if err != nil {
		return fmt.Errorf("Error Updating WAF Rule Group: %s", err)
	}

	return nil
}

func diffWafRuleGroupActivatedRules(oldRules, newRules []interface{}) []*waf.RuleGroupUpdate {
	updates := make([]*waf.RuleGroupUpdate, 0)

	for _, op := range oldRules {
		rule := op.(map[string]interface{})

		if idx, contains := sliceContainsMap(newRules, rule); contains {
			newRules = append(newRules[:idx], newRules[idx+1:]...)
			continue
		}

		updates = append(updates, &waf.RuleGroupUpdate{
			Action:        aws.String(waf.ChangeActionDelete),
			ActivatedRule: expandWafActivatedRule(rule),
		})
	}

	for _, np := range newRules {
		rule := np.(map[string]interface{})

		updates = append(updates, &waf.RuleGroupUpdate{
			Action:        aws.String(waf.ChangeActionInsert),
			ActivatedRule: expandWafActivatedRule(rule),
		})
	}
	return updates
}

func flattenWafActivatedRules(activatedRules []*waf.ActivatedRule) []interface{} {
	out := make([]interface{}, len(activatedRules), len(activatedRules))
	for i, ar := range activatedRules {
		rule := map[string]interface{}{
			"priority": int(*ar.Priority),
			"rule_id":  *ar.RuleId,
			"type":     *ar.Type,
		}
		if ar.Action != nil {
			rule["action"] = []interface{}{
				map[string]interface{}{
					"type": *ar.Action.Type,
				},
			}
		}
		if ar.OverrideAction != nil {
			rule["override_action"] = []interface{}{
				map[string]interface{}{
					"type": *ar.OverrideAction.Type,
				},
			}
		}
		out[i] = rule
	}
	return out
}

func expandWafActivatedRule(rule map[string]interface{}) *waf.ActivatedRule {
	r := &waf.ActivatedRule{
		Priority: aws.Int64(int64(rule["priority"].(int))),
		RuleId:   aws.String(rule["rule_id"].(string)),
		Type:     aws.String(rule["type"].(string)),
	}

	if a, ok := rule["action"].([]interface{}); ok && len(a) > 0 {
		m := a[0].(map[string]interface{})
		r.Action = &waf.WafAction{
			Type: aws.String(m["type"].(string)),
		}
	}
	if a, ok := rule["override_action"].([]interface{}); ok && len(a) > 0 {
		m := a[0].(map[string]interface{})
		r.OverrideAction = &waf.WafOverrideAction{
			Type: aws.String(m["type"].(string)),
		}
	}
	return r
}
