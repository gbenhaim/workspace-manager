package provision_test

import (
	"context"
	"net/http"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/konflux-ci/workspace-manager/pkg/test/utils"
	core "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestProvision(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Provision namespace Suite")
}

var k8sClient client.Client
var testEnv *envtest.Environment
var serverProcess *exec.Cmd
var serverCancelFunc context.CancelFunc

var _ = BeforeSuite(func() {
	schema := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(schema))
	testEnv = &envtest.Environment{BinaryAssetsDirectory: "../../../bin/k8s/1.29.0-linux-amd64/"}
	k8sClient = utils.StartTestEnv(schema, testEnv)
	serverProcess, serverCancelFunc = utils.CreateWorkspaceManagerServer(
		"../../../cmd/main.go",
		[]string{"WM_NS_PROVISION=true", "WM_HTTP_PORT=5001"},
		"",
	)
	utils.WaitForWorkspaceManagerServerToServe("http://localhost:5001/health")
})

var _ = AfterSuite(func() {
	utils.StopWorkspaceManagerServer(serverProcess, serverCancelFunc)
	utils.StopEnvTest(testEnv)
})

var _ = Describe("T", func() {
	endpoint := "http://localhost:5001/api/v1/signup"
	httpClient := &http.Client{}
	headers := map[string][]string{
		"X-Email": {"user1@konflux.dev"},
		"X-User":  {"abc123"},
	}

	Context("checking if a user has a namespace", func() {
		When("he/she doesn't have a namespace", func() {
			It("should return StatusNotFound", func() {
				request, err := http.NewRequest("GET", endpoint, nil)
				request.Header = headers
				Expect(err).NotTo(HaveOccurred())
				response, err := httpClient.Do(request)
				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode).Should(Equal(http.StatusNotFound))
			})
		})
	})

	Context("request to create a namespace for a user", func() {

		var ns *core.Namespace
		expectedNSName := "user1-konflux-dev-tenant"

		// Run the same test twice to ensure the handler is idempotent
		for i := 0; i < 2; i++ {
			When("requesting a namespace multiple times", func() {
				It("submits the request", func() {
					request, err := http.NewRequest("POST", endpoint, nil)
					request.Header = headers
					Expect(err).NotTo(HaveOccurred())
					response, err := httpClient.Do(request)
					Expect(err).NotTo(HaveOccurred())
					Expect(response.StatusCode).Should(Equal(http.StatusOK))

				})

				It("creates the namespace", func() {
					ns = &core.Namespace{}
					err := k8sClient.Get(
						context.TODO(),
						client.ObjectKey{
							Namespace: "",
							Name:      expectedNSName,
						},
						ns,
					)
					Expect(err).ToNot(HaveOccurred())
				})

				It("set the user's email in an annotation", func() {
					Expect(ns.Annotations).Should(
						HaveKeyWithValue(
							"konflux-ci.dev/requester-email",
							"user1@konflux.dev",
						),
					)
				})

				It("set the user's uuid in an annotation", func() {
					Expect(ns.Annotations).Should(
						HaveKeyWithValue(
							"konflux-ci.dev/requester-user-id",
							"abc123",
						),
					)
				})

				It("creates role binding for the user", func() {
					rb := &rbacv1.RoleBinding{}
					err := k8sClient.Get(
						context.TODO(),
						client.ObjectKey{
							Namespace: expectedNSName,
							Name:      "konflux-init-admin",
						},
						rb,
					)
					Expect(err).ToNot(HaveOccurred())
				})
			})
		}
	})

	Context("checking if a user has a namespace (after creating it)", func() {
		When("he/she has a namespace", func() {
			It("should return StatusOK", func() {
				request, err := http.NewRequest("GET", endpoint, nil)
				request.Header = headers
				Expect(err).NotTo(HaveOccurred())
				response, err := httpClient.Do(request)
				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode).Should(Equal(http.StatusOK))
			})
		})
	})

})
