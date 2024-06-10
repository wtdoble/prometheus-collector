package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	shared "github.com/prometheus-collector/shared"
	ccpconfigmapsettings "github.com/prometheus-collector/shared/configmap/ccp"
	configmapsettings "github.com/prometheus-collector/shared/configmap/mp"
)

func main() {
	controllerType := shared.GetControllerType()
	cluster := getEnv("CLUSTER", "")
	clusterOverride := getEnv("CLUSTER_OVERRIDE", "")
	aksRegion := getEnv("AKSREGION", "")
	ccpMetricsEnabled := getEnv("CCP_METRICS_ENABLED", "false")

	outputFile := "/opt/inotifyoutput.txt"
	if err := shared.Inotify(outputFile, "/etc/config/settings", "/etc/prometheus/certs"); err != nil {
		log.Fatal(err)
	}

	if ccpMetricsEnabled != "true" {
		if err := shared.SetupArcEnvironment(); err != nil {
			shared.EchoError(err.Error())
		}
	}

	mode := getEnv("MODE", "simple")

	shared.EchoVar("MODE", mode)
	shared.EchoVar("CONTROLLER_TYPE", getEnv("CONTROLLER_TYPE", ""))
	shared.EchoVar("CLUSTER", cluster)

	customEnvironment := getEnv("customEnvironment", "")
	if ccpMetricsEnabled != "true" {
		shared.SetupTelemetry(customEnvironment)
		if err := shared.ConfigureEnvironment(); err != nil {
			log.Fatalf("Error configuring environment: %v\n", err)
		}
	}

	if ccpMetricsEnabled == "true" {
		ccpconfigmapsettings.Configmapparserforccp()
	} else {
		configmapsettings.Configmapparser()
	}

	if ccpMetricsEnabled != "true" {
		startCronDaemon()
	}

	meConfigFile, fluentBitConfigFile := determineConfigFiles(controllerType, clusterOverride)
	fmt.Println("meConfigFile:", meConfigFile)
	fmt.Println("fluentBitConfigFile:", fluentBitConfigFile)

	waitForTokenAdapter(ccpMetricsEnabled)

	if ccpMetricsEnabled != "true" {
		shared.SetEnvAndSourceBashrc("ME_CONFIG_FILE", meConfigFile)
		shared.SetEnvAndSourceBashrc("customResourceId", cluster)
	} else {
		os.Setenv("ME_CONFIG_FILE", meConfigFile)
		os.Setenv("customResourceId", cluster)
	}

	trimmedRegion := strings.ToLower(strings.ReplaceAll(aksRegion, " ", ""))
	if ccpMetricsEnabled != "true" {
		shared.SetEnvAndSourceBashrc("customRegion", trimmedRegion)
	} else {
		os.Setenv("customRegion", trimmedRegion)
	}

	fmt.Println("Waiting for 10s for token adapter sidecar to be up and running...")
	time.Sleep(10 * time.Second)

	fmt.Println("Starting MDSD")
	if ccpMetricsEnabled != "true" {
		shared.StartMdsdForOverlay()
	} else {
		shared.StartMdsdForUnderlay()
	}

	shared.PrintMdsdVersion()

	fmt.Println("Waiting for 30s for MDSD to get the config and put them in place for ME")
	time.Sleep(30 * time.Second)

	fmt.Println("Starting Metrics Extension with config overrides")
	if ccpMetricsEnabled != "true" {
		if _, err := shared.StartMetricsExtensionForOverlay(meConfigFile); err != nil {
			log.Fatalf("Error starting MetricsExtension: %v\n", err)
		}
	} else {
		shared.StartMetricsExtensionWithConfigOverridesForUnderlay(meConfigFile)
	}

	logVersionInfo()

	if ccpMetricsEnabled != "true" {
		startFluentBit(fluentBitConfigFile)
		startTelegraf()
	}

	startInotify("/opt/inotifyoutput-mdsd-config.txt", "/etc/mdsd.d/config-cache/metricsextension/TokenConfig.json")

	writeContainerStartTime()

	http.HandleFunc("/health", healthHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func determineConfigFiles(controllerType, clusterOverride string) (string, string) {
	var meConfigFile, fluentBitConfigFile string

	switch {
	case strings.ToLower(controllerType) == "replicaset":
		fluentBitConfigFile = "/opt/fluent-bit/fluent-bit.conf"
		if clusterOverride == "true" {
			meConfigFile = "/usr/sbin/me_internal.config"
		} else {
			meConfigFile = "/usr/sbin/me.config"
		}
	case os.Getenv("OS_TYPE") != "windows":
		fluentBitConfigFile = "/opt/fluent-bit/fluent-bit.conf"
		if clusterOverride == "true" {
			meConfigFile = "/usr/sbin/me_ds_internal.config"
		} else {
			meConfigFile = "/usr/sbin/me_ds.config"
		}
	default:
		fluentBitConfigFile = "/opt/fluent-bit/fluent-bit-windows.conf"
		if clusterOverride == "true" {
			meConfigFile = "/usr/sbin/me_ds_internal_win.config"
		} else {
			meConfigFile = "/usr/sbin/me_ds_win.config"
		}
	}

	return meConfigFile, fluentBitConfigFile
}

func startCronDaemon() {
	cmd := exec.Command("/usr/sbin/crond", "-n", "-s")
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
}

func waitForTokenAdapter(ccpMetricsEnabled string) {
	tokenAdapterWaitSecs := 60
	if ccpMetricsEnabled == "true" {
		tokenAdapterWaitSecs = 20
	}
	waitedSecsSoFar := 1

	for {
		if waitedSecsSoFar > tokenAdapterWaitSecs {
			if _, err := http.Get("http://localhost:9999/healthz"); err != nil {
				log.Printf("giving up waiting for token adapter to become healthy after %d secs\n", waitedSecsSoFar)
				log.Printf("export tokenadapterUnhealthyAfterSecs=%d\n", waitedSecsSoFar)
				break
			}
		} else {
			log.Printf("checking health of token adapter after %d secs\n", waitedSecsSoFar)
			resp, err := http.Get("http://localhost:9999/healthz")
			if err == nil && resp.StatusCode == http.StatusOK {
				log.Printf("found token adapter to be healthy after %d secs\n", waitedSecsSoFar)
				log.Printf("export tokenadapterHealthyAfterSecs=%d\n", waitedSecsSoFar)
				break
			}
		}
		time.Sleep(1 * time.Second)
		waitedSecsSoFar++
	}
}

func logVersionInfo() {
	if meVersion, err := shared.ReadVersionFile("/opt/metricsextversion.txt"); err == nil {
		shared.FmtVar("ME_VERSION", meVersion)
	} else {
		log.Printf("Error reading ME version file: %v\n", err)
	}

	if golangVersion, err := shared.ReadVersionFile("/opt/goversion.txt"); err == nil {
		shared.FmtVar("GOLANG_VERSION", golangVersion)
	} else {
		log.Printf("Error reading Golang version file: %v\n", err)
	}

	if otelCollectorVersion, err := exec.Command("/opt/microsoft/otelcollector/otelcollector", "--version").Output(); err == nil {
		shared.FmtVar("OTELCOLLECTOR_VERSION", string(otelCollectorVersion))
	} else {
		log.Printf("Error getting otelcollector version: %v\n", err)
	}

	if prometheusVersion, err := shared.ReadVersionFile("/opt/microsoft/otelcollector/PROMETHEUS_VERSION"); err == nil {
		shared.FmtVar("PROMETHEUS_VERSION", prometheusVersion)
	} else {
		log.Printf("Error reading Prometheus version file: %v\n", err)
	}
}

func startFluentBit(fluentBitConfigFile string) {
	fmt.Println("Starting fluent-bit")

	if err := os.Mkdir("/opt/microsoft/fluent-bit", 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Error creating directory: %v\n", err)
	}

	logFile, err := os.Create("/opt/microsoft/fluent-bit/fluent-bit-out-appinsights-runtime.log")
	if err != nil {
		log.Fatalf("Error creating log file: %v\n", err)
	}
	defer logFile.Close()

	fluentBitCmd := exec.Command("fluent-bit", "-c", fluentBitConfigFile, "-e", "/opt/fluent-bit/bin/out_appinsights.so")
	fluentBitCmd.Stdout = os.Stdout
	fluentBitCmd.Stderr = os.Stderr
	if err := fluentBitCmd.Start(); err != nil {
		log.Fatalf("Error starting fluent-bit: %v\n", err)
	}
}

func startTelegraf() {
	fmt.Println("Starting Telegraf")

	if err := os.MkdirAll("/var/log/telegraf", 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Error creating directory: %v\n", err)
	}

	telegrafCmd := exec.Command("/usr/bin/telegraf", "--config", "/etc/telegraf/telegraf.conf")
	telegrafCmd.Stdout = os.Stdout
	telegrafCmd.Stderr = os.Stderr
	if err := telegrafCmd.Start(); err != nil {
		log.Fatalf("Error starting telegraf: %v\n", err)
	}
}

func startInotify(outputFile, configFile string) {
	if err := shared.Inotify(outputFile, configFile); err != nil {
		log.Fatal(err)
	}
}

func writeContainerStartTime() {
	containerStartTime := time.Now().Unix()
	if err := os.WriteFile("/opt/containerStartTime", []byte(strconv.FormatInt(containerStartTime, 10)), 0644); err != nil {
		log.Fatalf("Error writing container start time: %v\n", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	status := http.StatusOK
	message := "prometheuscollector is running."

	// Always running in MAC mode

	if _, err := os.Stat("/etc/mdsd.d/config-cache/metricsextension/TokenConfig.json"); os.IsNotExist(err) {
		if _, err := os.Stat("/opt/microsoft/liveness/azmon-container-start-time"); err == nil {
			azmonContainerStartTimeStr, err := os.ReadFile("/opt/microsoft/liveness/azmon-container-start-time")
			if err != nil {
				status = http.StatusServiceUnavailable
				message = "Error reading azmon-container-start-time: " + err.Error()
				goto response
			}

			azmonContainerStartTime, err := strconv.Atoi(strings.TrimSpace(string(azmonContainerStartTimeStr)))
			if err != nil {
				status = http.StatusServiceUnavailable
				message = "Error converting azmon-container-start-time to integer: " + err.Error()
				goto response
			}

			epochTimeNow := int(time.Now().Unix())
			duration := epochTimeNow - azmonContainerStartTime
			durationInMinutes := duration / 60

			if durationInMinutes%5 == 0 {
				message = fmt.Sprintf("%s No configuration present for the AKS resource\n", time.Now().Format("2006-01-02T15:04:05"))
			}

			if durationInMinutes > 15 {
				status = http.StatusServiceUnavailable
				message = "No configuration present for the AKS resource"
				goto response
			}
		}
	} else {
		if !shared.IsProcessRunning("/usr/sbin/MetricsExtension") {
			status = http.StatusServiceUnavailable
			message = "Metrics Extension is not running (configuration exists)"
			goto response
		}

		cmd := exec.Command("pgrep", "-f", "mdsd")
		output, err := cmd.Output()
		if err != nil || len(output) == 0 {
			status = http.StatusServiceUnavailable
			message = "mdsd is not running (configuration exists)"
			goto response
		}
	}

	if shared.HasConfigChanged("/opt/inotifyoutput-mdsd-config.txt") {
		status = http.StatusServiceUnavailable
		message = "inotifyoutput-mdsd-config.txt has been updated - mdsd config changed"
		goto response
	}

	if !shared.IsProcessRunning("/opt/microsoft/otelcollector/otelcollector") {
		status = http.StatusServiceUnavailable
		message = "OpenTelemetryCollector is not running."
		goto response
	}

	if shared.HasConfigChanged("/opt/inotifyoutput.txt") {
		status = http.StatusServiceUnavailable
		message = "inotifyoutput.txt has been updated - config changed"
		goto response
	}

response:
	w.WriteHeader(status)
	fmt.Fprintln(w, message)
	if status != http.StatusOK {
		fmt.Printf(message)
		shared.WriteTerminationLog(message)
	}
}
