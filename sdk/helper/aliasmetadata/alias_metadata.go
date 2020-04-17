package aliasmetadata

/*
aliasmetadata is a package offering convenience and
standardization when supporting an `alias_metadata`
field in a plugin's configuration. To see an example of
how to add and use it, check out how these structs
and fields are used in the AWS auth method.

Or, check out its acceptance test in this package to
see its integration points.
*/

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// Fields is for configuring a back-end's available
// default and additional fields. These are used for
// providing a verbose field description, and for parsing
// user input.
type Fields struct {
	// Default is a list of the default fields that should
	// be included if a user sends "default" in their list
	// of desired fields. These fields should all have a
	// low rate of change because each change can incur a
	// write to storage.
	Default []string

	// AvailableToAdd is a list of fields not included by
	// default, that the user may include.
	AvailableToAdd []string
}

// FieldName is the user-facing name for the field.
const FieldName = "alias_metadata"

// FieldSchema takes the default and additionally available
// fields, and uses them to generate a verbose description
// regarding how to use the "alias_metadata" field.
func FieldSchema(fields *Fields) *framework.FieldSchema {
	return &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: description(fields),
		DisplayAttrs: &framework.DisplayAttributes{
			Name:  FieldName,
			Value: "default,field1,field2",
		},
		Default: []string{"default"},
	}
}

// NewHandler instantiates a Handler to be embedded in your config.
func NewHandler(fields *Fields) Handler {
	return &handler{
		fields: fields,
	}
}

// Handler is an interface for the helper methods you get on your
// config when you embed the Handler.
type Handler interface {
	GetAliasMetadata() []string
	ParseAliasMetadata(data *framework.FieldData) error
	PopulateDesiredAliasMetadata(auth *logical.Auth, fieldValues map[string]string)
}

type handler struct {
	// AliasMetadata is an explicit list of all the user's configured
	// fields that are being added to alias metadata. It will never
	// include the "default" parameter, and instead includes the actual
	// fields behind "default", if selected. If it has never been set,
	// the pointer will be nil.
	AliasMetadata *[]string `json:"alias_metadata"`

	// fields is a list of the configured default and available
	// fields. It's intentionally not jsonified and therefore
	// isn't stored between runs, since this is configured by
	// our code and not the user.
	fields *Fields
}

// GetAliasMetadata is intended to be used on config reads.
// It gets an explicit list of all the user's configured
// fields that are being added to alias metadata. It will never
// include the "default" parameter, and instead includes the actual
// fields behind "default", if selected.
func (h *handler) GetAliasMetadata() []string {
	if h.AliasMetadata == nil {
		return h.fields.Default
	}
	return *h.AliasMetadata
}

// ParseAliasMetadata is intended to be used on config create/update.
// It takes a user's selected fields (or lack thereof),
// converts it to a list of explicit fields, and adds it to the handler
// for later storage.
func (h *handler) ParseAliasMetadata(data *framework.FieldData) error {
	userProvided, ok := data.GetOk(FieldName)
	if !ok {
		// Nothing further to do here.
		return nil
	}

	// uniqueFields protects against weird edge cases like if
	// a user provided "default,field1,field2,default".
	uniqueFields := make(map[string]bool)
	for _, field := range userProvided.([]string) {
		if field == "default" {
			// Add the fields that "default" represents, rather
			// than the explicit field.
			for _, dfltField := range h.fields.Default {
				uniqueFields[dfltField] = true
			}
		} else {
			// Make sure they've sent a supported field so we can
			// error early if not.
			if !strutil.StrListContains(append(h.fields.Default, h.fields.AvailableToAdd...), field) {
				return fmt.Errorf("%q is not an available field, please select from: %s", field, strings.Join(h.fields.AvailableToAdd, ", "))
			}
			uniqueFields[field] = true
		}
	}
	// Attach the fields we've received so they'll be stored.
	aliasMetadata := make([]string, len(uniqueFields))
	i := 0
	for fieldName := range uniqueFields {
		aliasMetadata[i] = fieldName
		i++
	}
	// Fulfilling the pointer here flags that the user has made
	// an explicit selection so we shouldn't just fall back to
	// our defaults.
	h.AliasMetadata = &aliasMetadata
	return nil
}

// PopulateDesiredAliasMetadata takes the available alias metadata and,
// if the auth should have it, adds it to the auth's alias metadata.
func (h *handler) PopulateDesiredAliasMetadata(auth *logical.Auth, available map[string]string) {
	fieldsToInclude := h.fields.Default
	if h.AliasMetadata != nil {
		fieldsToInclude = *h.AliasMetadata
	}
	for availableField, itsValue := range available {
		if strutil.StrListContains(fieldsToInclude, availableField) {
			auth.Alias.Metadata[availableField] = itsValue
		}
	}
}

func description(fields *Fields) string {
	desc := "The metadata to include on the aliases generated by this plugin."
	if len(fields.Default) > 0 {
		desc += fmt.Sprintf(" When set to 'default', includes: %s.", strings.Join(fields.Default, ", "))
	}
	if len(fields.AvailableToAdd) > 0 {
		desc += fmt.Sprintf(" These fields are available to add: %s.", strings.Join(fields.AvailableToAdd, ", "))
	}
	desc += " Not editing this field means the 'default' fields are included." +
		" Explicitly setting this field to empty overrides the 'default' and means no alias metadata will be included." +
		" Add fields by sending, 'default,field1,field2'." +
		" We advise only including fields that change rarely because each change triggers a storage write."
	return desc
}
