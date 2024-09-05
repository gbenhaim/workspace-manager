package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	authorizationv1 "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	authorizationv1Client "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	crt "github.com/codeready-toolchain/api/api/v1alpha1"
	"k8s.io/client-go/kubernetes"

	dummysignup "github.com/konflux-ci/workspace-manager/pkg/handlers/signup/dummy"

	provisioner "github.com/konflux-ci/workspace-manager/pkg/handlers/signup/provisioner"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

// Given all relevant user namespaces, return all workspaces for the calling user
func getWorkspacesWithAccess(
	e *echo.Echo, c echo.Context, allNamespaces []core.Namespace,
) (crt.WorkspaceList, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		e.Logger.Fatal(err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		e.Logger.Fatal(err)
	}

	authCl := clientset.AuthorizationV1()
	namespaces, err := getNamespacesWithAccess(e, c, authCl, allNamespaces)
	if err != nil {
		e.Logger.Fatal(err)
	}

	gv := crt.GroupVersion.String()

	var wss []crt.Workspace

	for _, ns := range namespaces {
		ws := crt.Workspace{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Workspace",
				APIVersion: gv,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: ns.Name,
			},
			Status: crt.WorkspaceStatus{
				Namespaces: []crt.SpaceNamespace{
					{
						Name: ns.Name,
						Type: "default",
					},
				},
				// Owner: "user1",
				// Role:  "admin",
			},
		}
		wss = append(wss, ws)
	}

	workspaces := crt.WorkspaceList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "WorkspaceList",
			APIVersion: gv,
		},
		Items: wss,
	}
	return workspaces, nil
}

// Get all the namespace in which the calling user is allowed to perform enough actions
// to allow workspace access
func getNamespacesWithAccess(
	e *echo.Echo,
	c echo.Context,
	authCl authorizationv1Client.AuthorizationV1Interface,
	allNamespaces []core.Namespace,
) ([]core.Namespace, error) {
	var allowedNs []core.Namespace
	for _, ns := range allNamespaces {
		notAllowed := false
		for _, verb := range []string{"create", "list", "watch", "delete"} {
			for _, resource := range []string{"applications", "components"} {
				allowed, err := runAccessCheck(
					authCl,
					c.Request().Header["X-Email"][0],
					ns.Name,
					"appstudio.redhat.com",
					resource,
					verb,
				)
				if err != nil || !allowed {
					e.Logger.Error(err)
					notAllowed = true
					break
				}
			}
			if notAllowed {
				break // skip next verbs
			}
		}
		if notAllowed {
			continue // move to next ns
		}
		allowedNs = append(allowedNs, ns)
	}
	return allowedNs, nil
}

// Gets all user namespaces that satisfy the provided requirement
func getUserNamespaces(e *echo.Echo, nameReq labels.Requirement) ([]core.Namespace, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		e.Logger.Fatal(err)
	}

	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		e.Logger.Fatal(err)
	}
	req, _ := labels.NewRequirement("konflux.ci/type", selection.In, []string{"user"})
	selector := labels.NewSelector().Add(*req)
	selector = selector.Add(nameReq)
	namespaceList := &core.NamespaceList{}
	err = cl.List(
		context.Background(),
		namespaceList,
		&client.ListOptions{LabelSelector: selector},
	)

	if err != nil {
		return nil, err
	}
	return namespaceList.Items, nil
}

// check if a user can perform a specific verb on a specific resource in namespace
func runAccessCheck(
	authCl authorizationv1Client.AuthorizationV1Interface,
	user string,
	namespace string,
	resourceGroup string,
	resource string,
	verb string,
) (bool, error) {
	sar := &authorizationv1.LocalSubjectAccessReview{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: user,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Group:     resourceGroup,
				Resource:  resource,
			},
		},
	}
	response, err := authCl.LocalSubjectAccessReviews(namespace).Create(
		context.TODO(), sar, metav1.CreateOptions{},
	)
	if err != nil {
		return false, err
	}
	if response.Status.Allowed {
		return true, nil
	}
	return false, nil
}

func getClientOrDie(logger echo.Logger) client.Client {
	cfg, err := config.GetConfig()
	if err != nil {
		logger.Fatal(err)
	}

	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		logger.Fatal(err)
	}

	return cl
}

func getHTTPPort() string {
	port := "5000"
	if val, ok := os.LookupEnv("WM_HTTP_PORT"); ok {
		port = val
	}

	return fmt.Sprintf(":%s", port)
}

func main() {
	e := echo.New()
	e.Logger.SetLevel(log.INFO)

	e.Pre(middleware.RemoveTrailingSlash())

	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	if os.Getenv("WM_NS_PROVISION") == "true" {
		e.Logger.Info("Automatic namespace provisioning is on")
		nsp := provisioner.NewNSProvisioner(getClientOrDie(e.Logger))
		e.POST("/api/v1/signup", nsp.CreateNSHandler)
		e.GET("/api/v1/signup", nsp.CheckNSExistHandler)
	} else {
		e.POST("/api/v1/signup", dummysignup.DummySignupPostHandler)
		e.GET("/api/v1/signup", dummysignup.DummySignupGetHandler)
	}

	e.GET("/workspaces", func(c echo.Context) error {
		nameReq, _ := labels.NewRequirement(
			"kubernetes.io/metadata.name", selection.Exists, []string{},
		)
		userNamespaces, err := getUserNamespaces(e, *nameReq)
		if err != nil {
			e.Logger.Fatal(err)
		}
		workspaces, err := getWorkspacesWithAccess(e, c, userNamespaces)
		if err != nil {
			e.Logger.Fatal(err)
		}

		return c.JSON(http.StatusOK, &workspaces)
	})

	e.GET("/workspaces/:ws", func(c echo.Context) error {
		nameReq, _ := labels.NewRequirement(
			"kubernetes.io/metadata.name", selection.In, []string{c.Param("ws")},
		)
		userNamespaces, err := getUserNamespaces(e, *nameReq)
		if err != nil {
			e.Logger.Fatal(err)
		}
		workspaces, err := getWorkspacesWithAccess(e, c, userNamespaces)
		if err != nil {
			e.Logger.Fatal(err)
		}

		wsParam := c.Param("ws")
		for _, ws := range workspaces.Items {
			if ws.Name == wsParam {
				return c.JSON(http.StatusOK, &ws)
			}
		}

		return echo.NewHTTPError(http.StatusNotFound)
	})

	e.GET("/health", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	e.Logger.Fatal(e.Start(getHTTPPort()))
}
