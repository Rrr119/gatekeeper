package dryrun

import (
	"fmt"

	frameworkapis "github.com/open-policy-agent/frameworks/constraint/pkg/apis"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/gator/reader"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

var scheme = runtime.NewScheme()

func init() {
	if err := frameworkapis.AddToScheme(scheme); err != nil {
		panic(fmt.Sprintf("dryrun: unable to register constraint framework APIs: %v", err))
	}
}

// Manifest is a classified set of Gatekeeper manifests. ConstraintTemplates
// are converted to the framework's versionless type; every other object is
// kept unstructured.
type Manifest struct {
	// Objects is every parsed object, in parse order.
	Objects []*unstructured.Unstructured

	// Templates are the parsed ConstraintTemplates in versionless form.
	Templates []*templates.ConstraintTemplate

	// Constraints are objects in the constraints.gatekeeper.sh group.
	Constraints []*unstructured.Unstructured

	// Resources are all objects that are neither templates nor constraints.
	Resources []*unstructured.Unstructured
}

// Parse parses one or more multi-document YAML or JSON byte slices and
// classifies the resulting objects. Existing v1 and v1beta1
// ConstraintTemplates are accepted and converted automatically.
func Parse(docs ...[]byte) (*Manifest, error) {
	m := &Manifest{}

	for _, doc := range docs {
		objs, err := reader.ReadUnstructureds(doc)
		if err != nil {
			return nil, fmt.Errorf("dryrun: parsing manifests: %w", err)
		}

		if err := m.Add(objs...); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// Classify sorts already-decoded objects into templates, constraints and
// resources and converts templates to the framework versionless type.
func Classify(objects ...*unstructured.Unstructured) (*Manifest, error) {
	m := &Manifest{}
	if err := m.Add(objects...); err != nil {
		return nil, err
	}

	return m, nil
}

// Add appends objects to the manifest, classifying each one.
func (m *Manifest) Add(objects ...*unstructured.Unstructured) error {
	for _, obj := range objects {
		if obj == nil {
			continue
		}

		m.Objects = append(m.Objects, obj)

		switch {
		case reader.IsTemplate(obj):
			tmpl, err := reader.ToTemplate(scheme, obj)
			if err != nil {
				return fmt.Errorf("dryrun: converting ConstraintTemplate %q: %w", obj.GetName(), err)
			}

			m.Templates = append(m.Templates, tmpl)
		case reader.IsConstraint(obj):
			m.Constraints = append(m.Constraints, obj)
		default:
			m.Resources = append(m.Resources, obj)
		}
	}

	return nil
}
