package utils

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Start the envtest environment
func StartTestEnv(scheme *runtime.Scheme, testEnv *envtest.Environment) client.Client {
	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error creating the envtest environment during test setup: %v", err))
	kubeconfigPath := CreateKubeconfigFileForRestConfig(*cfg)
	os.Setenv("KUBECONFIG", kubeconfigPath)
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error creating the client during test setup: %v", err))
	Expect(k8sClient).NotTo(BeNil())

	return k8sClient
}

// Stop the envtest environment
func StopEnvTest(envTest *envtest.Environment) {
	if envTest != nil {
		err := envTest.Stop()
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to stop envTest: %v", err))
	}
}

// Create a Kubeconfig from the given rest config.
func CreateKubeconfigFileForRestConfig(restConfig rest.Config) string {
	clusters := make(map[string]*clientcmdapi.Cluster)
	clusters["default-cluster"] = &clientcmdapi.Cluster{
		Server:                   restConfig.Host,
		CertificateAuthorityData: restConfig.CAData,
	}
	contexts := make(map[string]*clientcmdapi.Context)
	contexts["default-context"] = &clientcmdapi.Context{
		Cluster:  "default-cluster",
		AuthInfo: "default-user",
	}
	authinfos := make(map[string]*clientcmdapi.AuthInfo)
	authinfos["default-user"] = &clientcmdapi.AuthInfo{
		ClientCertificateData: restConfig.CertData,
		ClientKeyData:         restConfig.KeyData,
	}
	clientConfig := clientcmdapi.Config{
		Kind:           "Config",
		APIVersion:     "v1",
		Clusters:       clusters,
		Contexts:       contexts,
		CurrentContext: "default-context",
		AuthInfos:      authinfos,
	}
	kubeConfigFile, _ := os.CreateTemp("", "kubeconfig")
	_ = clientcmd.WriteToFile(clientConfig, kubeConfigFile.Name())
	return kubeConfigFile.Name()
}

// Build the workspace-manager binary.
// mainPath is the path to the main module.
func BuildWorkspaceManager(mainPath string) string {
	out := os.TempDir()
	binPath := filepath.Join(out, "workspace-manager", "manager")
	buildCmd := exec.Command("go", "build", "-o", binPath, mainPath)
	buildLog, err := buildCmd.CombinedOutput()
	Expect(err).NotTo(
		HaveOccurred(),
		"Failed to build the manager, %s\nBuild log: %s",
		err,
		buildLog,
	)

	return binPath
}

// Start workspace manager in the background. Return its backing Cmd and
// a function that can be used to kill its process.
// binPath is the path to the workspace-manager binary
// env is an array for specifying environment variables to be declared in the workspace-manager process.
// logFile is a file that will be used for storing workspace-manager stdout and stderr.
func StartWorkspaceManagerServer(binPath string, env []string, logFile *os.File) (*exec.Cmd, context.CancelFunc) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	serverCmd := exec.CommandContext(ctx, binPath)
	serverCmd.Env = append(os.Environ(), env...)
	serverCmd.Stderr = logFile
	serverCmd.Stdout = logFile
	err := serverCmd.Start()
	Expect(err).NotTo(
		HaveOccurred(),
		"Failed to start the manager, %s",
		err,
	)

	return serverCmd, cancelFunc
}

// Create a file in a temporary directory for storing workspace-manager output.
// The path to the log file will be printed so it can be seen in the output.
// of the test suite.
// dir is a directory for storing the file with the workspace-manager output.
// If empty the default temporary directory will be used.
func CreateLogFile(dir string) *os.File {
	tmpdir, err := os.MkdirTemp(dir, "workspace-manager")
	Expect(err).NotTo(HaveOccurred(), "Failed to create tempdir for the logs")
	logFile, err := os.Create(filepath.Join(tmpdir, "workspace-manager.log"))
	Expect(err).NotTo(HaveOccurred(), "Failed to create file for the workspace-manager log")
	fmt.Printf("workspace-manager logs will be written to: %s\n", logFile.Name())

	return logFile
}

// Wait for workspace-manager to start serving http requests
func WaitForWorkspaceManagerServerToServe(endpoint string) {
	httpClient := &http.Client{}
	request, err := http.NewRequest("GET", endpoint, nil)
	Expect(err).NotTo(HaveOccurred())
	fmt.Println("Waiting for workspace-manager to start. You may see some errors printed to the log.")
	Eventually(
		func() (int, error) {
			response, err := httpClient.Do(request)
			if err != nil {
				fmt.Println(err.Error())
				return 0, err
			}
			return response.StatusCode, nil

		},
		10,
		1,
	).Should(Equal(http.StatusOK), "Wait for Workspace Manager server to start")
}

// Build and start workspace-manager
// mainPath is the path to the main module
// env is an array for specifying environment variables to be declared in the workspace-manager process.
// logsDir is a directory for storing the file with the workspace-manager output.
// If empty the default temporary directory will be used.
func CreateWorkspaceManagerServer(mainPath string, env []string, logsDir string) (*exec.Cmd, context.CancelFunc) {
	return StartWorkspaceManagerServer(
		BuildWorkspaceManager(mainPath),
		env,
		CreateLogFile(logsDir),
	)
}

// Stop the workspace-manager process and wait for it to be stopped
func StopWorkspaceManagerServer(cmd *exec.Cmd, serverCancelFunc context.CancelFunc) {
	if cmd != nil {
		serverCancelFunc()
		err := cmd.Wait()
		Expect(err).Should(BeAssignableToTypeOf(&exec.ExitError{}))
	}
}
