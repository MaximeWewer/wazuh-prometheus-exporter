package exporter

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Node manager-style metrics (status, logs, info, config validity, daily stats),
// driven through the standalone path of the cluster collector (/manager/*).

func TestNode_StatusInfoConfig(t *testing.T) {
	e := newNodeExporter(map[string]string{
		"/manager/status":                   `{"data":{"affected_items":[{"wazuh-analysisd":"running","wazuh-dbd":"stopped"}]}}`,
		"/manager/info":                     `{"data":{"affected_items":[{"version":"v4.14.5","type":"server","max_agents":14000}]}}`,
		"/manager/configuration/validation": `{"data":{"total_failed_items":0,"affected_items":[{"name":"manager","status":"OK"}]}}`,
		"/manager/stats":                    `{"error":1308,"message":"no stats file"}`,
		"/manager/logs/summary":             `{"data":{"affected_items":[{"wazuh-analysisd":{"all":19,"info":18,"error":1,"warning":0,"critical":0,"debug":0}}]}}`,
	})

	expDaemon := `
# HELP wazuh_manager_daemon_up Whether a Wazuh manager daemon is running (1) or not (0).
# TYPE wazuh_manager_daemon_up gauge
wazuh_manager_daemon_up{daemon="wazuh-analysisd",node="manager"} 1
wazuh_manager_daemon_up{daemon="wazuh-dbd",node="manager"} 0
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expDaemon), "wazuh_manager_daemon_up"); err != nil {
		t.Errorf("daemon_up: %v", err)
	}
	expInfo := `
# HELP wazuh_manager_info Wazuh manager metadata as a constant 1, labelled by type and version.
# TYPE wazuh_manager_info gauge
wazuh_manager_info{node="manager",type="server",version="v4.14.5"} 1
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expInfo), "wazuh_manager_info"); err != nil {
		t.Errorf("manager_info: %v", err)
	}
	expValid := `
# HELP wazuh_manager_config_valid Whether the manager configuration validates (1) or has errors (0).
# TYPE wazuh_manager_config_valid gauge
wazuh_manager_config_valid{node="manager"} 1
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expValid), "wazuh_manager_config_valid"); err != nil {
		t.Errorf("config_valid: %v", err)
	}
	expMax := `
# HELP wazuh_manager_max_agents Maximum number of agents the manager accepts.
# TYPE wazuh_manager_max_agents gauge
wazuh_manager_max_agents{node="manager"} 14000
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expMax), "wazuh_manager_max_agents"); err != nil {
		t.Errorf("max_agents: %v", err)
	}
	// stats endpoint returned error 1308 → no daily aggregate series.
	if n := testutil.CollectAndCount(e, "wazuh_manager_alerts_total"); n != 0 {
		t.Errorf("stats 1308 → no alerts series, got %d", n)
	}
	// logs: 5 levels emitted ("all" dropped).
	expLogs := `
# HELP wazuh_manager_logs_total Manager log entries by component tag and level.
# TYPE wazuh_manager_logs_total counter
wazuh_manager_logs_total{level="critical",node="manager",tag="wazuh-analysisd"} 0
wazuh_manager_logs_total{level="debug",node="manager",tag="wazuh-analysisd"} 0
wazuh_manager_logs_total{level="error",node="manager",tag="wazuh-analysisd"} 1
wazuh_manager_logs_total{level="info",node="manager",tag="wazuh-analysisd"} 18
wazuh_manager_logs_total{level="warning",node="manager",tag="wazuh-analysisd"} 0
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expLogs), "wazuh_manager_logs_total"); err != nil {
		t.Errorf("logs_total: %v", err)
	}
}

func TestNode_HourlyWeeklyStats(t *testing.T) {
	e := newNodeExporter(map[string]string{
		"/manager/stats/hourly": `{"data":{"affected_items":[{"averages":[5,0,0,12],"interactions":17}]}}`,
		"/manager/stats/weekly": `{"data":{"affected_items":[
			{"Mon":{"hours":[1,2],"interactions":3}},
			{"Tue":{"hours":[0,4],"interactions":4}}
		]}}`,
	})
	expH := `
# HELP wazuh_manager_hourly_alerts_average Average alerts per hour of the day (0-23), from Wazuh's hourly stats profile.
# TYPE wazuh_manager_hourly_alerts_average gauge
wazuh_manager_hourly_alerts_average{hour="00",node="manager"} 5
wazuh_manager_hourly_alerts_average{hour="01",node="manager"} 0
wazuh_manager_hourly_alerts_average{hour="02",node="manager"} 0
wazuh_manager_hourly_alerts_average{hour="03",node="manager"} 12
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expH), "wazuh_manager_hourly_alerts_average"); err != nil {
		t.Errorf("hourly: %v", err)
	}
	expW := `
# HELP wazuh_manager_weekly_alerts_average Average alerts per weekday and hour, from Wazuh's weekly stats profile.
# TYPE wazuh_manager_weekly_alerts_average gauge
wazuh_manager_weekly_alerts_average{day="Mon",hour="00",node="manager"} 1
wazuh_manager_weekly_alerts_average{day="Mon",hour="01",node="manager"} 2
wazuh_manager_weekly_alerts_average{day="Tue",hour="00",node="manager"} 0
wazuh_manager_weekly_alerts_average{day="Tue",hour="01",node="manager"} 4
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expW), "wazuh_manager_weekly_alerts_average"); err != nil {
		t.Errorf("weekly: %v", err)
	}
}

func TestNode_DailyStatsSummed(t *testing.T) {
	e := newNodeExporter(map[string]string{
		"/manager/stats": `{"data":{"affected_items":[{"totalAlerts":10,"events":100,"syscheck":4,"firewall":1},{"totalAlerts":5,"events":50,"syscheck":1,"firewall":0}]}}`,
	})
	exp := `
# HELP wazuh_manager_alerts_total Alerts logged by the manager today (sum of hourly totals).
# TYPE wazuh_manager_alerts_total counter
wazuh_manager_alerts_total{node="manager"} 15
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(exp), "wazuh_manager_alerts_total"); err != nil {
		t.Errorf("alerts_total (summed): %v", err)
	}
}
