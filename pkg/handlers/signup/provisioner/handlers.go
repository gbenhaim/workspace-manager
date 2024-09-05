package provisioner

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	core "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/konflux-ci/workspace-manager/pkg/api/v1alpha1"
)

const (
	UserEmailAnnotation string = "konflux-ci.dev/requester-email"
	UserIdAnnotation    string = "konflux-ci.dev/requester-user-id"
)

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

func NewNSProvisioner(k8sClient client.Client) *NSProvisioner {
	return &NSProvisioner{
		k8sClient: k8sClient,
	}
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
			&v1alpha1.Signup{
				SignupStatus: v1alpha1.SignupStatus{
					Ready:  true,
					Reason: v1alpha1.SignedUp,
				},
			},
		)
	}

	if !errors.IsNotFound(err) {
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(
		http.StatusNotFound,
		&v1alpha1.Signup{
			SignupStatus: v1alpha1.SignupStatus{
				Ready:  false,
				Reason: v1alpha1.NotSignedUp,
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
