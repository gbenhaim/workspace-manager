package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	authorizationv1 "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	authorizationv1Client "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	crt "github.com/codeready-toolchain/api/api/v1alpha1"
	"k8s.io/client-go/kubernetes"

	dummysignup "github.com/konflux-ci/workspace-manager/pkg/handlers/signup/dummy"
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
	selector.Add(nameReq)
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

func nopSignupPostHandler(c echo.Context) error {
	return c.String(http.StatusOK, "ok")
}

func nopSignupGetHandler(c echo.Context) error {
	resp := &Signup{
		SignupStatus: SignupStatus{
			Ready:  true,
			Reason: SignedUp,
		},
	}
	return c.JSON(http.StatusOK, resp)
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

func normalizeEmail(email string) string {
	ret := strings.Replace(email, "@", "-", -1)
	ret = strings.Replace(ret, "+", "-", -1)
	ret = strings.Replace(ret, ".", "-", -1)
	ret = strings.ToLower(ret)
	suffix := "-tenant"
	if len(ret+suffix) > 63 {
		return ret[:63-len(suffix)] + suffix
	}

	return ret + suffix

}

type NSProvisioner struct {
	k8sClient client.Client
}

func (nsp *NSProvisioner) CheckNSExistHandler(c echo.Context) error {
	email := c.Request().Header["X-Email"][0]
	c.Logger().Info("Checking if namespace exists for user ", email)
	nsName := normalizeEmail(email)
	c.Logger().Info("Normalized namespace name  ", nsName)

	ns := &core.Namespace{}
	err := nsp.k8sClient.Get(
		c.Request().Context(),
		client.ObjectKey{
			Namespace: "",
			Name:      nsName,
		},
		ns,
	)

	if err == nil {
		return c.JSON(
			http.StatusOK,
			&Signup{
				SignupStatus: SignupStatus{
					Ready:  true,
					Reason: SignedUp,
				},
			},
		)
	}

	if !errors.IsNotFound(err) {
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(
		http.StatusNotFound,
		&v1alpha1Signup{
			SignupStatus: SignupStatus{
				Ready:  false,
				Reason: NotSignedUp,
			},
		},
	)

}

func (nsp *NSProvisioner) CreateNSHandler(c echo.Context) error {
	// add X-User as a label/annotation
	// add the original user email as label/annotation

	email := c.Request().Header["X-Email"][0]
	userId := c.Request().Header["X-User"][0]
	c.Logger().Info("Creating namespace for user ", email)
	nsName := normalizeEmail(email)
	c.Logger().Info("Normalized namespace name  ", nsName)

	ns := &core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "",
			Name:      nsName,
			Labels: map[string]string{
				"konflux.ci/type": "user",
			},
			Annotations: map[string]string{
				UserEmailAnnotation: email,
				UserIdAnnotation:    userId,
			},
		},
	}

	err := nsp.k8sClient.Create(c.Request().Context(), ns)

	if errors.IsAlreadyExists(err) {
		c.Logger().Infof("Namespace %s already exists", nsName)
	} else if err != nil {
		c.Logger().Errorf("Failed to create namespace %s, %s", nsName, err.Error())
		return c.NoContent(http.StatusInternalServerError)
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: nsName,
			Name:      "konflux-init-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				APIGroup: "rbac.authorization.k8s.io",
				Name:     email,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "konflux-admin-user-actions",
		},
	}

	err = nsp.k8sClient.Create(c.Request().Context(), rb)
	if errors.IsAlreadyExists(err) {
		c.Logger().Warn("Role binding for the initial admin already exists.")
	} else if err != nil {
		c.Logger().Errorf(
			"Failed to create admin role binding for user %s, %s",
			email,
			err.Error(),
		)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.String(
		http.StatusOK,
		fmt.Sprintf(
			"namespace creation request for %s was completed successfully",
			nsName,
		),
	)
}

func main() {
	e := echo.New()
	e.Logger.SetLevel(log.INFO)

	e.Pre(middleware.RemoveTrailingSlash())

	e.Use(middleware.RequestID())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/api/v1/signup", dummysignup.DummySignupPostHandler)

	e.GET("/api/v1/signup", dummysignup.DummySignupGetHandler)
	if os.Getenv("NS_PROVISION") == "true" {
		e.Logger.Info("Automatic namespace provisioning is on")
		nsp := NSProvisioner{k8sClient: getClientOrDie(e.Logger)}
		e.POST("/api/v1/signup", nsp.CreateNSHandler)
		e.GET("/api/v1/signup", nsp.CheckNSExistHandler)
	} else {
		e.POST("/api/v1/signup", nopSignupPostHandler)
		e.GET("/api/v1/signup", nopSignupGetHandler)
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

	e.Logger.Fatal(e.Start(":5000"))
}
