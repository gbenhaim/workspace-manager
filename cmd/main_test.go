package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	k8sapi "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/kubernetes"

	"context"
	"net/http/httptest"
	"testing"

	crt "github.com/codeready-toolchain/api/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/konflux-ci/workspace-manager/pkg/test/utils"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

type HTTPResponse struct {
	Body       string
	StatusCode int
}

type HTTPheader struct {
	name  string
	value string
}

type NamespaceRoleBinding struct {
	Namespace   string
	Role        string
	RoleBinding string
}

var k8sClient client.Client
var testEnv *envtest.Environment

func createRole(k8sClient client.Client, nsName string, roleName string, verbs []string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: nsName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"appstudio.redhat.com"},
				Resources: []string{"applications", "components"},
				Verbs:     verbs,
			},
		},
	}
	err := k8sClient.Create(context.Background(), role)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error creating 'Role' resource: %v", err))
}

func createRoleBinding(k8sClient client.Client, bindingName string, nsName string, userName string, roleName string) {
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: nsName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     userName,
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     roleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
	err := k8sClient.Create(context.Background(), roleBinding)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error creating 'roleBinding' resource: %v", err))
}

func createNamespace(k8sClient client.Client, name string) (k8sapi.Namespace, error) {
	namespaced := &k8sapi.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"konflux.ci/type":             "user",
				"kubernetes.io/metadata.name": name,
			},
		},
	}
	if err := k8sClient.Create(context.Background(), namespaced); err != nil {
		return k8sapi.Namespace{}, fmt.Errorf("Error creating 'Namespace' resource: %v", err)
	}
	return *namespaced, nil
}

func deleteRole(k8sClient client.Client, nsName string, roleName string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: nsName,
		},
	}
	err := k8sClient.Delete(context.Background(), role)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error deleting the role %s in namespace %s: %v\n", roleName, nsName, err))
}

func deleteRoleBinding(k8sClient client.Client, nsName string, roleBindingName string) {
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName,
			Namespace: nsName,
		},
	}
	err := k8sClient.Delete(context.Background(), roleBinding)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error deleting the role binding %s in namespace %s: %v\n", roleBindingName, nsName, err))
}

func deleteNamespace(k8sClient client.Client, nsName string) {
	ns := &k8sapi.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
		},
	}
	err := k8sClient.Delete(context.Background(), ns)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error deleting the namespace: %s: %v\n", nsName, err))
}

func performHTTPGetCall(url string, header HTTPheader) (*HTTPResponse, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating request: %s", err)
		return nil, err
	}
	if header.name != "" {
		req.Header.Add(header.name, header.value)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body:  %s", err)
		return nil, err
	}
	response := &HTTPResponse{
		Body:       string(body),
		StatusCode: resp.StatusCode,
	}
	return response, nil
}

func TestCmd(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Main Suite")
}

var _ = Describe("Signup endpoint", func() {
	Context("Calling the signup endpoint with GET", func() {
		It("responds with ready and signedup", func() {
			url := "http://localhost:5000/api/v1/signup"
			expectedCode := http.StatusOK
			expectedBody := `{"status":{"ready":true,"reason":"SignedUp"}}`

			resp, err := performHTTPGetCall(url, HTTPheader{})
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Unexpected error testing the \"%s\" endpoint: %v", url, err))
			Expect(resp.StatusCode).To(Equal(expectedCode))
			Expect(strings.TrimSpace(expectedBody)).To(Equal(strings.TrimSpace(resp.Body)))
		})
	})
})

var _ = DescribeTable("Workspace endpoint", func(header HTTPheader, expectedCode int, expectedBody string) {
	url := "http://localhost:5000/workspaces"
	resp, err := performHTTPGetCall(url, header)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Unexpected error testing the \"%s\" endpoint: %v", url, err))
	Expect(resp.StatusCode).To(Equal(expectedCode))
	Expect(strings.TrimSpace(expectedBody)).To(Equal(strings.TrimSpace(resp.Body)))
},
	Entry(
		"Calling the workspace endpoint for user1 responds only with the 'test-tenant' workspace info",
		HTTPheader{"X-Email", "user1@konflux.dev"},
		http.StatusOK,
		`{"kind":"WorkspaceList","apiVersion":"toolchain.dev.openshift.com/v1alpha1","metadata":{},`+
			`"items":[{"kind":"Workspace","apiVersion":"toolchain.dev.openshift.com/v1alpha1",`+
			`"metadata":{"name":"test-tenant","creationTimestamp":null},"status":`+
			`{"namespaces":[{"name":"test-tenant","type":"default"}]}}]}`),
	Entry(
		"Workspace endpoint for user2 responds with 2 namespaces info",
		HTTPheader{"X-Email", "user2@konflux.dev"},
		http.StatusOK,
		`{"kind":"WorkspaceList","apiVersion":"toolchain.dev.openshift.com/v1alpha1","metadata":{},`+
			`"items":[{"kind":"Workspace","apiVersion":"toolchain.dev.openshift.com/v1alpha1",`+
			`"metadata":{"name":"test-tenant","creationTimestamp":null},"status":{"namespaces":`+
			`[{"name":"test-tenant","type":"default"}]}},{"kind":"Workspace","apiVersion":`+
			`"toolchain.dev.openshift.com/v1alpha1","metadata":{"name":"test-tenant-2",`+
			`"creationTimestamp":null},"status":{"namespaces":[{"name":"test-tenant-2",`+
			`"type":"default"}]}}]}`),
	Entry(
		"Workspace endpoint for user3 responds with no namespaces",
		HTTPheader{"X-Email", "user3@konflux.dev"},
		http.StatusOK,
		`{"kind":"WorkspaceList","apiVersion":"toolchain.dev.openshift.com/v1alpha1","metadata":{},"items":null}`),
	Entry(
		"Workspace endpoint with no header",
		HTTPheader{},
		500,
		`{"message":"Internal Server Error"}`),
)

var _ = DescribeTable("Specific workspace endpoint", func(endpoint string, header HTTPheader, expectedCode int, expectedBody string) {
	url := "http://localhost:5000/workspaces/" + endpoint
	resp, err := performHTTPGetCall(url, header)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Unexpected error testing the \"%s\" endpoint: %v", url, err))
	Expect(resp.StatusCode).To(Equal(expectedCode))
	Expect(strings.TrimSpace(expectedBody)).To(Equal(strings.TrimSpace(resp.Body)))
},
	Entry(
		"Calling the workspace endpoint for the test-tenant workspace for user2",
		"test-tenant",
		HTTPheader{"X-Email", "user2@konflux.dev"},
		http.StatusOK,
		`{"kind":"Workspace","apiVersion":"toolchain.dev.openshift.com/v1alpha1","metadata":`+
			`{"name":"test-tenant","creationTimestamp":null},"status":{"namespaces":`+
			`[{"name":"test-tenant","type":"default"}]}}`),
	Entry(
		"Specific workspace endpoint for test-tenant-2 for user1 only",
		"test-tenant-2",
		HTTPheader{"X-Email", "user1@konflux.dev"},
		404,
		`{"message":"Not Found"}`),
)

var serverProcess *exec.Cmd
var serverCancelFunc context.CancelFunc

var _ = BeforeSuite(func() {
	schema := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(schema))
	testEnv = &envtest.Environment{BinaryAssetsDirectory: "../bin/k8s/1.29.0-linux-amd64/"}
	k8sClient = utils.StartTestEnv(schema, testEnv)

	serverProcess, serverCancelFunc = utils.CreateWorkspaceManagerServer("main.go", nil, "")
	utils.WaitForWorkspaceManagerServerToServe("http://localhost:5000/health")

	user1 := "user1@konflux.dev"
	user2 := "user2@konflux.dev"
	namespaceNames := []string{"test-tenant", "test-tenant-2", "test-tenant-3"}
	for _, name := range namespaceNames {
		_, err := createNamespace(k8sClient, name)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error while creating the namespace %s: %v", name, err))
	}
	createRole(k8sClient, "test-tenant", "namespace-access", []string{"create", "list", "watch", "delete"})
	createRole(k8sClient, "test-tenant-2", "namespace-access-2", []string{"create", "list", "watch", "delete"})
	createRoleBinding(k8sClient, "namespace-access-user-binding", "test-tenant", user1, "namespace-access")
	createRoleBinding(k8sClient, "namespace-access-user-binding-2", "test-tenant", user2, "namespace-access")
	createRoleBinding(k8sClient, "namespace-access-user-binding-3", "test-tenant-2", user2, "namespace-access-2")

	time.Sleep(3 * time.Second)
})

var _ = AfterSuite(func() {
	utils.StopWorkspaceManagerServer(serverProcess, serverCancelFunc)
	utils.StopEnvTest(testEnv)
})

var _ = DescribeTable("TestRunAccessCheck", func(user string, namespace string, resource string, verb string, expectedResult bool) {
	cfg, _ := config.GetConfig()
	clientset, _ := kubernetes.NewForConfig(cfg)
	authCl := clientset.AuthorizationV1()

	boolresult, err := runAccessCheck(authCl, user, namespace, "appstudio.redhat.com", resource, verb)
	Expect(boolresult).To(Equal(expectedResult))
	Expect(err).NotTo(HaveOccurred(), "Unexpected error testing RunAccessCheck")
},
	Entry(
		"A user that has access to the resource should return true (user2 has permission to 'create' on test-tenant-1)",
		"user2@konflux.dev",
		"test-tenant",
		"applications",
		"create",
		true),
	Entry(
		"A user that does not have any premissions on the namespace should return false (user1 doesn't have access to test-tenant-2)",
		"user1@konflux.dev",
		"test-tenant-2",
		"applications",
		"create",
		false),
	Entry(
		"A user that does not have the permissions to perform the specific action on the namespace should return false (user1 doesn't have permission to 'patch' on test-tenant-1)",
		"user1@konflux.dev",
		"test-tenant-1",
		"applications",
		"patch",
		false),
)

var _ = DescribeTable("GetWorkspacesWithAccess querying for workspaces with access", func(gv string, allNamespaces []k8sapi.Namespace, expectedWorkspaces []crt.Workspace) {
	e := echo.New()
	c := e.NewContext(nil, nil)
	Context("When workspace test-tenant's namespaces has all the necessary permissions", func() {
		namespaceNames := []string{"ws-test-tenant-1", "ws-test-tenant-2"}
		roleNames := []string{"ws-namespace-access-1", "ws-namespace-access-2"}
		roleBindings := []string{"ws-namespace-access-user-binding-1", "ws-namespace-access-user-binding-2"}
		BeforeEach(func() {
			gv = "v1alpha1"
			for i, name := range namespaceNames {
				ns, err := createNamespace(k8sClient, name)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error while creating the namespace %s: %v", name, err))
				allNamespaces = append(allNamespaces, ns)
				createRole(k8sClient, name, roleNames[i], []string{"create", "list", "watch", "delete"})
				createRoleBinding(k8sClient, roleBindings[i], name, "user1@konflux.dev", roleNames[i])
			}
			expectedWorkspaces = []crt.Workspace{
				{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Workspace",
						APIVersion: gv,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ws-test-tenant-1",
					},
					Status: crt.WorkspaceStatus{
						Namespaces: []crt.SpaceNamespace{
							{
								Name: "ws-test-tenant-1",
								Type: "default",
							},
						},
					},
				},
				{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Workspace",
						APIVersion: gv,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ws-test-tenant-2",
					},
					Status: crt.WorkspaceStatus{
						Namespaces: []crt.SpaceNamespace{
							{
								Name: "ws-test-tenant-2",
								Type: "default",
							},
						},
					},
				},
			}
		})

		It("Should return a WorkspaceList with test-tenant workspace and both namespaces in it", func() {
			actualWorkspaces, err := getWorkspacesWithAccess(e, c, allNamespaces)
			Expect(actualWorkspaces.Items).To(Equal(expectedWorkspaces))
			Expect(err).NotTo(HaveOccurred(), "Unexpected error testing GetWorkspacesWithAccess")
		})

		AfterEach(func() {
			for i, name := range namespaceNames {
				deleteRoleBinding(k8sClient, name, roleBindings[i])
				deleteRole(k8sClient, name, roleNames[i])
				deleteNamespace(k8sClient, name)
			}
		})
	})

	Context("When workspace with only test-tenant namespace has all the necessary permissions", func() {
		namespaceNames := []string{"ws-test-tenant-1", "ws-test-tenant-2"}
		BeforeEach(func() {
			gv = "v1alpha1"
			for _, name := range namespaceNames {
				ns, err := createNamespace(k8sClient, name)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error while creating the namespace %s: %v", name, err))
				allNamespaces = append(allNamespaces, ns)
			}
			createRole(k8sClient, "ws-test-tenant-1", "ws-namespace-access-1", []string{"create", "list", "watch", "delete"})
			createRoleBinding(k8sClient, "ws-namespace-access-user-binding-1", "ws-test-tenant-1", "user1@konflux.dev", "ws-namespace-access-1")
			expectedWorkspaces = []crt.Workspace{
				{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Workspace",
						APIVersion: gv,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ws-test-tenant-1",
					},
					Status: crt.WorkspaceStatus{
						Namespaces: []crt.SpaceNamespace{
							{
								Name: "ws-test-tenant-1",
								Type: "default",
							},
						},
					},
				},
			}
		})

		It("Should return a WorkspaceList with test-tenant workspace and only test-tenant namespace in it", func() {
			actualWorkspaces, err := getWorkspacesWithAccess(e, c, allNamespaces)
			Expect(actualWorkspaces.Items).To(Equal(expectedWorkspaces))
			Expect(err).NotTo(HaveOccurred(), "Unexpected error testing GetWorkspacesWithAccess")
		})

		AfterEach(func() {
			deleteRoleBinding(k8sClient, "ws-test-tenant-1", "ws-namespace-access-user-binding-1")
			deleteRole(k8sClient, "ws-test-tenant-1", "ws-namespace-access-1")
			for _, name := range namespaceNames {
				deleteNamespace(k8sClient, name)
			}
		})
	})

	Context("When no workspaces has all the necessary permissions", func() {
		namespaceNames := []string{"ws-test-tenant-1", "ws-test-tenant-2"}
		BeforeEach(func() {
			gv = "v1alpha1"
			for _, name := range namespaceNames {
				ns, err := createNamespace(k8sClient, name)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error while creating the namespace %s: %v", name, err))
				allNamespaces = append(allNamespaces, ns)
			}
			createRole(k8sClient, "ws-test-tenant-1", "ws-namespace-access-1", []string{"create", "list"})
			createRoleBinding(k8sClient, "ws-namespace-access-user-binding-1", "ws-test-tenant-1", "user1@konflux.dev", "ws-namespace-access-1")
			expectedWorkspaces = []crt.Workspace{}
		})

		It("Should return a empty WorkspaceList", func() {
			actualWorkspaces, err := getWorkspacesWithAccess(e, c, allNamespaces)
			Expect(actualWorkspaces.Items).To(Equal(expectedWorkspaces))
			Expect(err).NotTo(HaveOccurred(), "Unexpected error testing GetWorkspacesWithAccess")
		})

		AfterEach(func() {
			deleteRoleBinding(k8sClient, "ws-test-tenant-1", "ws-namespace-access-user-binding-1")
			deleteRole(k8sClient, "ws-test-tenant-1", "ws-namespace-access-1")
			for _, name := range namespaceNames {
				deleteNamespace(k8sClient, name)
			}
		})
	})
})

var _ = DescribeTable("TestGetNamespacesWithAccess", func(allNamespaces []k8sapi.Namespace,
	expectedNs []k8sapi.Namespace, actualNs []k8sapi.Namespace, err error) {
	e := echo.New()
	cfg, _ := config.GetConfig()
	clientset, _ := kubernetes.NewForConfig(cfg)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Request().Header.Set("X-Email", "user1@konflux.dev")
	authCl := clientset.AuthorizationV1()

	JustBeforeEach(func() {
		actualNs, err = getNamespacesWithAccess(e, c, authCl, allNamespaces)
	})

	Context("When all the namespaces have all the necessary permissions like create, list, watch and delete", func() {
		mappings := []NamespaceRoleBinding{
			{
				Namespace:   "ns-test-tenant-1",
				Role:        "ns-namespace-access-1",
				RoleBinding: "ns-namespace-access-user-binding-1",
			},
			{
				Namespace:   "ns-test-tenant-2",
				Role:        "ns-namespace-access-2",
				RoleBinding: "ns-namespace-access-user-binding-2",
			},
		}
		BeforeEach(func() {
			for _, name := range mappings {
				ns, err := createNamespace(k8sClient, name.Namespace)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error while creating the namespace %s: %v", name.Namespace, err))
				allNamespaces = append(allNamespaces, ns)
				createRole(k8sClient, name.Namespace, name.Role, []string{"create", "list", "watch", "delete"})
				createRoleBinding(k8sClient, name.RoleBinding, name.Namespace, "user1@konflux.dev", name.Role)
			}
			expectedNs = allNamespaces
		})
		It("returns all namespaces in the list", func() {
			Expect(actualNs).To(Equal(expectedNs))
			Expect(err).NotTo(HaveOccurred(), "Unexpected error testing GetNamespacesWithAccess")
		})
		AfterEach(func() {
			for _, name := range mappings {
				deleteRoleBinding(k8sClient, name.Namespace, name.RoleBinding)
				deleteRole(k8sClient, name.Namespace, name.Role)
				deleteNamespace(k8sClient, name.Namespace)
			}
		})
	})

	Context("When namspace ns3 doesn't have necessary permissions", func() {
		BeforeEach(func() {
			var ns3 k8sapi.Namespace
			ns3, err = createNamespace(k8sClient, "ns-test-tenant-3")
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error while creating the namespace ns3: %v", err))
			allNamespaces = []k8sapi.Namespace{ns3}
			expectedNs = []k8sapi.Namespace{}
		})
		It("doesn't return any namespace", func() {
			Expect(actualNs).To(Equal(expectedNs))
			Expect(err).NotTo(HaveOccurred(), "Unexpected error testing GetNamespacesWithAccess")
		})
		AfterEach(func() {
			deleteNamespace(k8sClient, "ns-test-tenant-3")
		})
	})

	Context("When only namespaces ns-test-tenant-1 and ns-test-tenant-2 has all necessary permissions and other's don't", func() {
		mappings := []NamespaceRoleBinding{
			{
				Namespace:   "ns-test-tenant-1",
				Role:        "ns-namespace-access-1",
				RoleBinding: "ns-namespace-access-user-binding-1",
			},
			{
				Namespace:   "ns-test-tenant-2",
				Role:        "ns-namespace-access-2",
				RoleBinding: "ns-namespace-access-user-binding-2",
			},
			{
				Namespace:   "ns-test-tenant-3",
				Role:        "ns-namespace-access-3",
				RoleBinding: "ns-namespace-access-user-binding-3",
			},
			{
				Namespace:   "ns-test-tenant-4",
				Role:        "",
				RoleBinding: "",
			},
		}
		BeforeEach(func() {
			for _, name := range mappings {
				ns, err := createNamespace(k8sClient, name.Namespace)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error while creating the namespace %s: %v", name.Namespace, err))
				allNamespaces = append(allNamespaces, ns)
			}
			createRole(k8sClient, "ns-test-tenant-1", "ns-namespace-access-1", []string{"create", "list", "watch", "delete"})
			createRole(k8sClient, "ns-test-tenant-2", "ns-namespace-access-2", []string{"create", "list", "watch", "delete"})
			createRole(k8sClient, "ns-test-tenant-3", "ns-namespace-access-3", []string{"create", "list", "watch"})
			createRoleBinding(k8sClient, "ns-namespace-access-user-binding-1", "ns-test-tenant-1", "user1@konflux.dev", "ns-namespace-access-1")
			createRoleBinding(k8sClient, "ns-namespace-access-user-binding-2", "ns-test-tenant-2", "user2@konflux.dev", "ns-namespace-access-2")
			createRoleBinding(k8sClient, "ns-namespace-access-user-binding-3", "ns-test-tenant-3", "user3@konflux.dev", "ns-namespace-access-3")
			expectedNs = append(expectedNs, allNamespaces[0], allNamespaces[1])
		})
		It("returns only namespaces test-tenant and test-tenant-2", func() {
			Expect(actualNs).To(Equal(expectedNs))
			Expect(err).NotTo(HaveOccurred(), "Unexpected error testing GetNamespacesWithAccess")
		})
		AfterEach(func() {
			deleteRoleBinding(k8sClient, "ns-test-tenant-1", "ns-namespace-access-user-binding-1")
			deleteRoleBinding(k8sClient, "ns-test-tenant-2", "ns-namespace-access-user-binding-2")
			deleteRoleBinding(k8sClient, "ns-test-tenant-3", "ns-namespace-access-user-binding-3")
			deleteRole(k8sClient, "ns-test-tenant-1", "ns-namespace-access-1")
			deleteRole(k8sClient, "ns-test-tenant-2", "ns-namespace-access-2")
			deleteRole(k8sClient, "ns-test-tenant-3", "ns-namespace-access-3")
			for _, name := range mappings {
				deleteNamespace(k8sClient, name.Namespace)
			}
		})
	})
})

var _ = Describe("GetUserNamespaces", func() {
	var e *echo.Echo
	var createdNamespaces []string

	// checks if all created namespaces are in the returned list
	Context("When querying for all user namespaces using Exists", func() {
		It("Should return all created namespaces", func() {
			namesToCreate := []string{"test-ns-1", "test-ns-2", "test-ns-3"}
			for _, name := range namesToCreate {
				ns, err := createNamespace(k8sClient, name)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error creating the namespace %s", name))
				createdNamespaces = append(createdNamespaces, ns.Name)
			}

			req, err := labels.NewRequirement("kubernetes.io/metadata.name", selection.Exists, []string{})
			Expect(err).NotTo(HaveOccurred(), "Error creating label requirement")

			namespaces, err := getUserNamespaces(e, *req)
			Expect(err).NotTo(HaveOccurred(), "Error getting user namespaces")

			var actualNamespaces []string
			for _, ns := range namespaces {
				actualNamespaces = append(actualNamespaces, ns.Name)
			}

			for _, createdNs := range createdNamespaces {
				Expect(actualNamespaces).To(ContainElement(createdNs))
			}
		})

		AfterEach(func() {
			for _, ns := range createdNamespaces {
				deleteNamespace(k8sClient, ns)
			}
			createdNamespaces = nil
		})
	})
	// checks if specific namespaces are in the returned list
	Context("When querying for specific namespaces using In", func() {
		It("Should return only the specified namespaces", func() {
			for _, name := range []string{"in-test-1", "in-test-2", "not-in-test"} {
				ns, err := createNamespace(k8sClient, name)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error creating the namespace %s", name))
				createdNamespaces = append(createdNamespaces, ns.Name)
			}

			req, err := labels.NewRequirement("kubernetes.io/metadata.name", selection.In, []string{"in-test-1", "in-test-2"})
			Expect(err).NotTo(HaveOccurred(), "Error creating label requirement")

			namespaces, err := getUserNamespaces(e, *req)
			Expect(err).NotTo(HaveOccurred(), "Error getting user namespaces")

			var actualNamespaces []string
			for _, ns := range namespaces {
				actualNamespaces = append(actualNamespaces, ns.Name)
			}

			Expect(actualNamespaces).To(ConsistOf("in-test-1", "in-test-2"))
			Expect(actualNamespaces).NotTo(ContainElement("not-in-test"))
		})

		AfterEach(func() {
			for _, ns := range createdNamespaces {
				deleteNamespace(k8sClient, ns)
			}
		})
	})

	Context("When querying for namespaces using NotIn", func() {
		It("Should return namespaces not in the specified list", func() {
			for _, name := range []string{"ts-keep-1", "ts-keep-2", "ts-exclude-1", "ts-exclude-2"} {
				ns, err := createNamespace(k8sClient, name)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Error creating the namespace %s", name))
				createdNamespaces = append(createdNamespaces, ns.Name)
			}

			req, err := labels.NewRequirement("kubernetes.io/metadata.name", selection.NotIn, []string{"ts-exclude-1", "ts-exclude-2"})
			Expect(err).NotTo(HaveOccurred(), "Error creating label requirement")

			namespaces, err := getUserNamespaces(e, *req)
			Expect(err).NotTo(HaveOccurred(), "Error getting user namespaces")

			var actualNamespaces []string
			for _, ns := range namespaces {
				actualNamespaces = append(actualNamespaces, ns.Name)
			}

			Expect(actualNamespaces).To(ContainElements("ts-keep-1", "ts-keep-2"))
			Expect(actualNamespaces).NotTo(ContainElements("ts-exclude-1", "ts-exclude-2"))
		})

		AfterEach(func() {
			for _, ns := range createdNamespaces {
				deleteNamespace(k8sClient, ns)
			}
		})
	})
})
