package regionTests

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"prometheus-collector/otelcollector/test/utils"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd" //*************NEW - WTD***************************
)

var (
	K8sClient             *kubernetes.Clientset
	Cfg                   *rest.Config
	PrometheusQueryClient v1.API
	parmRuleName          string
	parmAmwResourceId     string
	azureClientId         string
	//parmKubeconfigPath    string //*************NEW - WTD***************************
	//v                     bool
	//verboseLogging        bool = false
)

const namespace = "kube-system"
const containerName = "prometheus-collector"
const controllerLabelName = "rsName"
const controllerLabelValue = "ama-metrics"
const AZURE_CLIENT_ID = "AZURE_CLIENT_ID"

func init() {
	//flag.StringVar(&parmKubeconfigPath, "kubeconfig", "", "Path to the kubeconfig file") //*************NEW - WTD***************************
	flag.StringVar(&parmRuleName, "parmRuleName", "", "Prometheus rule name to use in this test suite")
	flag.StringVar(&parmAmwResourceId, "parmAmwResourceId", "", "AMW resource id to use in this test suite")
	flag.StringVar(&azureClientId, "clientId", "", "Azure Client ID to use in this test suite")
}

func TestTest(t *testing.T) {
	flag.Parse()
	RegisterFailHandler(Fail)
	RunSpecs(t, "Test Suite")
}

func getKubeClient() (*kubernetes.Clientset, *rest.Config, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(os.TempDir(), "kubeconfig.yaml")
	}

	fmt.Printf("env (KUBECONFIG): %s\r\n", kubeconfig)
	Expect(kubeconfig).NotTo(BeEmpty())

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, nil, err
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, cfg, nil
}

var envConfig = cloud.Configuration{

	ActiveDirectoryAuthorityHost: "https://login.microsoftonline.eaglex.ic.gov/",
	Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
		cloud.ResourceManager: {
			Endpoint: "https://management.azure.eaglex.ic.gov/",
			Audience: "https://management.azure.eaglex.ic.gov/",
		},
		// // cloud.Storage: {
		// // 	// If using storage data-plane clients; adjust endpoint and audience if required.
		// // 	// Endpoint is often per-account, so set in the service client instead.
		// // 	Audience: "https://storage.azure.eaglex.ic.gov/",
		// // },
		// // cloud.KeyVault: {
		// // 	Endpoint: "https://vault.azure.eaglex.ic.gov",
		// // 	Audience: "https://vault.azure.eaglex.ic.gov/",
		// // },
		// add more services as needed
	},
}

func createDefaultAzureCredential(options *azidentity.DefaultAzureCredentialOptions) (*azidentity.DefaultAzureCredential, error) {

	if options == nil {
		options = &azidentity.DefaultAzureCredentialOptions{}
	}

	options.ClientOptions.Cloud = envConfig
	cred, err := azidentity.NewDefaultAzureCredential(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create default azure credential: %w", err)
	}
	return cred, nil
}

// //////////////////////////////////////////////////
func getQueryAccessToken(amwQueryEndpoint string) (string, error) {
	cred, err := createDefaultAzureCredential(nil) //(nil)
	if err != nil {
		return "", fmt.Errorf("Failed to create identity credential: %s", err.Error())
	}

	u, err := url.Parse(amwQueryEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid AMW_QUERY_ENDPOINT: %w", err)
	}

	scope := "https://" + u.Host + "/.default" // e.g., https://prometheus.monitor.azure.eaglex.ic.gov/.default

	opts := policy.TokenRequestOptions{
		Scopes: []string{scope},
	}

	accessToken, err := cred.GetToken(context.Background(), opts)
	if err != nil {
		return "", fmt.Errorf("failed to get accesstoken: %s", err.Error())
	}

	return accessToken.Token, nil
}

/*
 * The custom Prometheus API transport with the bearer token.
 */
type transport struct {
	underlyingTransport http.RoundTripper
	apiToken            string
}

/*
 * The custom RoundTrip with the bearer token added to the request header.
 */
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t.apiToken))
	return t.underlyingTransport.RoundTrip(req)
}

/*
 * Create a Prometheus API client to use with the Managed Prometheus AMW Query API.
 */
func createPromApiManagedClient(amwQueryEndpoint string) (v1.API, error) {
	token, err := getQueryAccessToken(amwQueryEndpoint)
	if err != nil {
		return nil, fmt.Errorf("Failed to get query access token: %s", err.Error())
	}
	if token == "" {
		return nil, fmt.Errorf("Failed to get query access token: token is empty")
	}
	config := api.Config{
		Address:      amwQueryEndpoint,
		RoundTripper: &transport{underlyingTransport: http.DefaultTransport, apiToken: token},
	}
	prometheusAPIClient, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("Failed to create Prometheus API client: %s", err.Error())
	}
	return v1.NewAPI(prometheusAPIClient), nil
}

////////////////////////////////

// func GetQueryAccessToken() (string, error) {
// 	cred, err := azidentity.NewDefaultAzureCredential(nil)
// 	if err != nil {
// 		return "", fmt.Errorf("Failed to create identity credential: %s", err.Error())
// 	}

// 	opts := policy.TokenRequestOptions{
// 		Scopes: []string{"https://prometheus.monitor.azure.com"},
// 	}

// 	accessToken, err := cred.GetToken(context.Background(), opts)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to get accesstoken: %s", err.Error())
// 	}

// 	return accessToken.Token, nil
// }

// func getManagedIdentityToken() (string, error) {
// 	// Replace with your user-assigned managed identity client ID
// 	clientID := "de61beff-a8f7-4016-810d-2a744c5fe868"

// 	// Create a ManagedIdentityCredential using the client ID
// 	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
// 		ID: azidentity.ClientID(clientID),
// 	})
// 	if err != nil {
// 		return "", fmt.Errorf("failed to create managed identity credential: %s", err.Error())
// 	}

// 	// Request a token for Prometheus Monitor scope
// 	opts := policy.TokenRequestOptions{
// 		Scopes: []string{"https://prometheus.monitor.azure.com/.default"},
// 	}

// 	accessToken, err := cred.GetToken(context.Background(), opts)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to get access token: %s", err.Error())
// 	}

// 	return accessToken.Token, nil
// }
////////////////////////////////////////////////////////////////
// // func getQueryAccessToken() (string, error) {
// // 	identityEndpoint := os.Getenv("IDENTITY_ENDPOINT")
// // 	identityHeader := os.Getenv("IDENTITY_HEADER")
// // 	resource := "https://prometheus.monitor.azure.com"
// // 	principalId := "529f7b78-240a-4dd1-baf5-f3e500d8e2fb"

// // 	fmt.Println("Are auto-injected identity variables present?")
// // 	// If Azure-injected identity variables are present, use them
// // 	if identityEndpoint != "" && identityHeader != "" {
// // 		log.Printf("Using injected identity endpoint: %s", identityEndpoint)
// // 		log.Printf("Using injected identity header: %s", identityHeader)

// // 		// Construct query string
// // 		query := fmt.Sprintf("resource=%s&principalId=%s", url.QueryEscape(resource), url.QueryEscape(principalId))
// // 		fullURL := fmt.Sprintf("%s&%s", identityEndpoint, query)

// // 		log.Printf("Full GET URL: %s", fullURL)

// // 		req, err := http.NewRequest("GET", fullURL, nil)
// // 		if err != nil {
// // 			return "", fmt.Errorf("failed to create GET request to IDENTITY_ENDPOINT: %w", err)
// // 		}

// // 		req.Header.Add("secret", identityHeader)
// // 		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

// // 		client := &http.Client{}
// // 		resp, err := client.Do(req)
// // 		if err != nil {
// // 			return "", fmt.Errorf("failed to call IDENTITY_ENDPOINT: %w", err)
// // 		}
// // 		defer resp.Body.Close()

// // 		log.Printf("Response status: %s", resp.Status)
// // 		respBody, _ := ioutil.ReadAll(resp.Body)
// // 		log.Printf("Response body: %s", string(respBody))

// // 		if resp.StatusCode != http.StatusOK {
// // 			return "", fmt.Errorf("failed to get token from IDENTITY_ENDPOINT: %s", string(respBody))
// // 		}

// // 		var tokenResp struct {
// // 			AccessToken string `json:"access_token"`
// // 		}
// // 		if err := json.Unmarshal(respBody, &tokenResp); err != nil {
// // 			return "", fmt.Errorf("failed to decode token response: %w", err)
// // 		}

// // 		log.Printf("Access token acquired successfully.")
// // 		return tokenResp.AccessToken, nil
// // 	}

// // 	fmt.Println("IDENTITY_ENDPOINT or IDENTITY_HEADER not set, falling back to DefaultAzureCredential")
// // 	//log.Println("IDENTITY_ENDPOINT or IDENTITY_HEADER not set. Falling back to DefaultAzureCredential.")
// // 	return getFallbackAccessToken(resource)
// // }

// // func getFallbackAccessToken(resource string) (string, error) {
// // 	c := azcore.ClientOptions{
// // 		Cloud: cloud.AzurePublic,
// // 	}
// // 	d := &azidentity.DefaultAzureCredentialOptions{
// // 		ClientOptions: c,
// // 	}
// // 	cred, err := azidentity.NewDefaultAzureCredential(d)
// // 	if err != nil {
// // 		return "", fmt.Errorf("DefaultAzureCredential creation failed: %w", err)
// // 	}

// // 	opts := policy.TokenRequestOptions{
// // 		Scopes: []string{resource},
// // 	}

// // 	accessToken, err := cred.GetToken(context.Background(), opts)
// // 	if err != nil {
// // 		return "", fmt.Errorf("DefaultAzureCredential failed to get token: %w", err)
// // 	}

// // 	log.Printf("Fallback access token acquired successfully.")
// // 	return accessToken.Token, nil
// // }

// // /*
// //  * The custom Prometheus API transport with the bearer token.
// //  */
// // type transport struct {
// // 	underlyingTransport http.RoundTripper
// // 	apiToken            string
// // }

// // /*
// //  * The custom RoundTrip with the bearer token added to the request header.
// //  */
// // func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
// // 	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t.apiToken))
// // 	return t.underlyingTransport.RoundTrip(req)
// // }

// // func createPromApiManagedClient(amwQueryEndpoint string) (v1.API, error) {
// // 	token, err := getQueryAccessToken()
// // 	if err != nil {
// // 		return nil, fmt.Errorf("Failed to get managed identity access token: %s", err.Error())
// // 	}
// // 	if token == "" {
// // 		return nil, fmt.Errorf("Failed to get query managed identity access token: token is empty")
// // 	}
// // 	config := api.Config{
// // 		Address:      amwQueryEndpoint,
// // 		RoundTripper: &transport{underlyingTransport: http.DefaultTransport, apiToken: token},
// // 	}
// // 	prometheusAPIClient, err := api.NewClient(config)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("Failed to create Prometheus API client: %s", err.Error())
// // 	}
// // 	return v1.NewAPI(prometheusAPIClient), nil
// // }

var _ = BeforeSuite(func() {
	var err error
	fmt.Println("Getting kube client")
	K8sClient, Cfg, err = getKubeClient() ////****** NEW - WTD ************** utils.SetupKubernetesClient()
	Expect(err).NotTo(HaveOccurred())

	amwQueryEndpoint := os.Getenv("AMW_QUERY_ENDPOINT")
	fmt.Printf("env (AMW_QUERY_ENDPOINT): %s\r\n", amwQueryEndpoint)
	Expect(amwQueryEndpoint).NotTo(BeEmpty())

	////PrometheusQueryClient, err = utils.CreatePrometheusAPIClient(amwQueryEndpoint)
	fmt.Println("Getting prom api client")
	PrometheusQueryClient, err = createPromApiManagedClient(amwQueryEndpoint)
	Expect(err).NotTo(HaveOccurred())
	Expect(PrometheusQueryClient).NotTo(BeNil())

	fmt.Printf("parmRuleName: %s\r\n", parmRuleName)
	Expect(parmRuleName).ToNot(BeEmpty())

	fmt.Printf("parmAmwResourceId: %s\r\n", parmAmwResourceId)
	Expect(parmAmwResourceId).ToNot(BeEmpty())

	// fmt.Printf("parmVerbose: %s\r\n", parmVerbose)
	// Expect(strings.ToLower(parmVerbose)).To(BeElementOf([]string{"true", "false"}), "parmVerbose must be either 'true' or 'false'.")

	////azureClientId = os.Getenv(AZURE_CLIENT_ID)
	fmt.Printf("Setting env variable %s to %s\r\n", AZURE_CLIENT_ID, azureClientId)
	_ = os.Setenv(AZURE_CLIENT_ID, azureClientId)
	fmt.Printf("azureClientId: %s\r\n", azureClientId)
	Expect(azureClientId).NotTo(BeEmpty())
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
})

func readFile(fileName string, podName string) []string {
	fmt.Printf("Examining %s\r\n", fileName)
	var cmd []string = []string{"cat", fileName}
	stdout, _, err := utils.ExecCmd(K8sClient, Cfg, podName, containerName, namespace, cmd)
	Expect(err).To(BeNil())

	return strings.Split(stdout, "\n")
}

func writeLines(lines []string) int {
	count := 0
	for _, rawLine := range lines {
		//fmt.Printf("raw line #%d: %s\r\n", i, rawLine)
		line := strings.Trim(rawLine, " ")
		if len(line) > 0 {
			//fmt.Printf("line #%d: %s\r\n", i, line)
			fmt.Printf("%s\r\n", line)
			count++
		} else {
			fmt.Println("<empty line>")
		}
	}

	return count
}

func safeDereferenceFloatPtr(f *float64) float64 {
	if f != nil {
		return *f
	}
	return 0.0
}

var _ = Describe("Regions Suite", func() {

	const mdsdErrFileName = "/opt/microsoft/linuxmonagent/mdsd.err"
	const mdsdInfoFileName = "/opt/microsoft/linuxmonagent/mdsd.info"
	const mdsdWarnFileName = "/opt/microsoft/linuxmonagent/mdsd.warn"
	const metricsExtDebugLogFileName = "/MetricsExtensionConsoleDebugLog.log"
	const metricsextension = "/etc/mdsd.d/config-cache/metricsextension"
	const ERROR = "error"
	const WARN = "warn"

	var podName string = ""

	type metricExtConsoleLine struct {
		line   string
		dt     string
		status string
		data   string
	}

	BeforeEach(func() {
		v1Pod, err := utils.GetPodsWithLabel(K8sClient, namespace, controllerLabelName, controllerLabelValue)
		Expect(err).To(BeNil())
		Expect(len(v1Pod)).To(BeNumerically(">", 0))

		fmt.Printf("pod array length: %d\r\n", len(v1Pod))
		fmt.Printf("Available pods matching '%s'='%s'\r\n", controllerLabelName, controllerLabelValue)
		for _, p := range v1Pod {
			fmt.Println(p.Name)
		}

		if len(v1Pod) > 0 {
			podName = v1Pod[0].Name
			fmt.Printf("Choosing the pod: %s\r\n", podName)
		}

		Expect(podName).ToNot(BeEmpty())
	})

	Context("Examine selected files and directories", func() {

		It("Check that there are no errors in /opt/microsoft/linuxmonagent/mdsd.err", func() {

			numErrLines := writeLines(readFile(mdsdErrFileName, podName))
			if numErrLines > 0 {
				fmt.Printf("%s is not empty.\r\n", mdsdErrFileName)
				writeLines(readFile(mdsdInfoFileName, podName))
				writeLines(readFile(mdsdWarnFileName, podName))
			}

			Expect(numErrLines).To(Equal(0))
		})

		It("Enumerate all the 'error' or 'warning' records in /MetricsExtensionConsoleDebugLog.log", func() {

			var lines []string = readFile(metricsExtDebugLogFileName, podName)
			count := 0

			// for i := 0; i < 10; i++ {
			// 	line := lines[i]
			for _, line := range lines {
				//fmt.Printf("#line: %d, %s \r\n", i, line)

				var fields []string = strings.Fields(line)
				if len(fields) > 2 {
					metricExt := metricExtConsoleLine{line: line, dt: fields[0], status: fields[1], data: fields[2]}
					//fmt.Println(metricExt.status)
					status := strings.ToLower(metricExt.status)
					if strings.Contains(status, ERROR) || strings.Contains(status, WARN) {
						fmt.Println(line)
						count++
					}
				}
			}

			Expect(count).To(Equal(0))
		})

		It("Check that /etc/mdsd.d/config-cache/metricsextension exists", func() {

			var cmd []string = []string{"ls", "/etc/mdsd.d/config-cache/"}
			stdout, _, err := utils.ExecCmd(K8sClient, Cfg, podName, containerName, namespace, cmd)
			Expect(err).To(BeNil())

			metricsExtExists := false

			list := strings.Split(stdout, "\n")
			for i := 0; i < len(list) && !metricsExtExists; i++ {
				s := list[i]
				fmt.Println(s)
				metricsExtExists = (strings.Compare(s, "metricsextension") == 0)
			}

			Expect(metricsExtExists).To(BeTrue())

			fmt.Printf("%s exists.\r\n", metricsextension)
		})
	})

	Context("Examine Prometheus via the AMW", func() {
		It("Query for a metric", func() {
			query := "up"

			fmt.Printf("Examining metrics via the query: '%s'\r\n", query)

			warnings, result, err := utils.InstantQuery(PrometheusQueryClient, query)
			Expect(err).NotTo(HaveOccurred())
			Expect(warnings).To(BeEmpty())

			// Ensure there is at least one result
			vectorResult, ok := result.(model.Vector)
			Expect(ok).To(BeTrue(), "Result should be of type model.Vector")
			Expect(vectorResult).NotTo(BeEmpty(), "Result should not be empty")

			fmt.Printf("%d metrics were returned from the query.\r\n", vectorResult.Len())
		})

		It("Query the specified recording rule", func() {
			fmt.Printf("Examining the recording rule: %s", parmRuleName)

			warnings, result, err := utils.InstantQuery(PrometheusQueryClient, parmRuleName)

			fmt.Println(warnings)
			Expect(err).NotTo(HaveOccurred())

			// Ensure there is at least one result
			vectorResult, ok := result.(model.Vector)
			Expect(ok).To(BeTrue(), "Result should be of type model.Vector")
			Expect(vectorResult).NotTo(BeEmpty(), "Result should not be empty")
		})

		It("Query Prometheus alerts", func() {
			warnings, result, err := utils.InstantQuery(PrometheusQueryClient, "alerts")

			fmt.Println(warnings)
			Expect(err).NotTo(HaveOccurred())

			fmt.Println(result)
		})

		It("Query Azure Monitor for AMW usage and limits metrics", func() {
			////cred, err := azidentity.NewDefaultAzureCredential(nil)

			// Create a credential using the specific client ID
			////clientID := "de61beff-a8f7-4016-810d-2a744c5fe868"
			cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
				ID: azidentity.ClientID(azureClientId),
				ClientOptions: azcore.ClientOptions{
					Cloud: envConfig,
				},
			})
			if err != nil {
				log.Fatalf("failed to create managed identity credential: %v", err)
			}

			Expect(err).NotTo(HaveOccurred())

			client, err := azquery.NewMetricsClient(cred,
				&azquery.MetricsClientOptions{
					ClientOptions: azcore.ClientOptions{
						Cloud: envConfig, // our EAGLEX cloud.Configuration
					},
				},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(client).ToNot(BeNil())

			var response azquery.MetricsClientQueryResourceResponse
			timespan := azquery.TimeInterval("PT30M")
			metricNames := "ActiveTimeSeriesLimit,ActiveTimeSeriesPercentUtilization"
			response, err = client.QueryResource(context.Background(),
				parmAmwResourceId,
				&azquery.MetricsClientQueryResourceOptions{
					Timespan:        to.Ptr(timespan),
					Interval:        to.Ptr("PT5M"),
					MetricNames:     &metricNames,
					Aggregation:     to.SliceOfPtrs(azquery.AggregationTypeAverage, azquery.AggregationTypeCount),
					Top:             nil,
					OrderBy:         to.Ptr("Average asc"),
					Filter:          nil,
					ResultType:      nil,
					MetricNamespace: nil,
				})

			Expect(err).NotTo(HaveOccurred())

			fmt.Printf("%d Metrics returned\r\n", len(response.Response.Value))
			for i, v := range response.Response.Value {
				var a azquery.Metric = *v
				fmt.Printf("ID[%d]: %s\r\n", i, *(a.ID))
				fmt.Printf("Timeseries length: %d\r\n", len(a.TimeSeries))

				Expect(a.TimeSeries).NotTo(BeNil())
				for j, t := range a.TimeSeries {
					fmt.Printf("TimeSeries #%d\r\n", j)

					Expect(t.Data).NotTo(BeNil())
					for k, d := range t.Data {
						// fmt.Printf("%d - ", k)
						// fmt.Print((*d).TimeStamp.GoString())
						fmt.Printf("%d - %s - Average(%f); Count(%f); Max(%f); Min(%f); Total(%f);\r\n",
							k, (*d).TimeStamp.GoString(),
							safeDereferenceFloatPtr((*d).Average),
							safeDereferenceFloatPtr((*d).Count),
							safeDereferenceFloatPtr((*d).Maximum),
							safeDereferenceFloatPtr((*d).Minimum),
							safeDereferenceFloatPtr((*d).Total))
					}
				}
			}
		})
	})
})
