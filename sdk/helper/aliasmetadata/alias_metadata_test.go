package aliasmetadata

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestAcceptance(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	b := &fakeBackend{
		Backend: &framework.Backend{
			Paths: []*framework.Path{
				configPath(),
				loginPath(),
			},
		},
	}
	if err := b.Setup(ctx, &logical.BackendConfig{
		StorageView: storage,
		Logger:      hclog.Default(),
	}); err != nil {
		t.Fatal(err)
	}

	// TODO now start sending requests configuring it and reading what's set,
	// and what's on the auth metadata.
}

// We expect people to embed the handler on their
// config so it automatically makes its helper methods
// available and easy to find wherever the config is
// needed. Explicitly naming it in json avoids it
// automatically being named "Handler" by Go's JSON
// marshalling library.
type fakeConfig struct {
	Handler `json:"alias_metadata_handler"`
}

type fakeBackend struct {
	*framework.Backend
}

// We expect each back-end to explicitly define the fields that
// will be included by default, and optionally available.
var aliasMetadataFields = &Fields{
	Default: []string{
		"role_name", // This would likely never change because the alias is the role name.
	},
	AvailableToAdd: []string{
		"remote_addr", // This would likely change with every new caller.
	},
}

func configPath() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			FieldName: FieldSchema(aliasMetadataFields),
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
					entryRaw, err := req.Storage.Get(ctx, "config")
					if err != nil {
						return nil, err
					}
					conf := &fakeConfig{}
					if entryRaw != nil {
						if err := entryRaw.DecodeJSON(conf); err != nil {
							return nil, err
						}
					}
					// Note that even if the config entry was nil, we return
					// a populated response to give info on what the default
					// alias metadata is when unconfigured.
					return &logical.Response{
						Data: map[string]interface{}{
							FieldName: conf.GetAliasMetadata(),
						},
					}, nil
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
					entryRaw, err := req.Storage.Get(ctx, "config")
					if err != nil {
						return nil, err
					}
					conf := &fakeConfig{}
					if entryRaw != nil {
						if err := entryRaw.DecodeJSON(conf); err != nil {
							return nil, err
						}
					}
					// This is where we read in the user's given alias metadata.
					if err := conf.ParseAliasMetadata(fd); err != nil {
						// Since this will only error on bad input, it's best to give
						// a 400 response with the explicit problem included.
						return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
					}
					entry, err := logical.StorageEntryJSON("config", conf)
					if err != nil {
						return nil, err
					}
					if err = req.Storage.Put(ctx, entry); err != nil {
						return nil, err
					}
					return nil, nil
				},
			},
		},
	}
}

func loginPath() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"role_name": {
				Type:     framework.TypeString,
				Required: true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, fd *framework.FieldData) (*logical.Response, error) {
					entryRaw, err := req.Storage.Get(ctx, "config")
					if err != nil {
						return nil, err
					}
					conf := &fakeConfig{}
					if entryRaw != nil {
						if err := entryRaw.DecodeJSON(conf); err != nil {
							return nil, err
						}
					}
					auth := &logical.Auth{
						Alias: &logical.Alias{
							Name: fd.Get("role_name").(string),
						},
					}
					// Here we will only add what was configured as wanted earlier.
					conf.PopulateDesiredAliasMetadata(auth, map[string]string{
						"role_name":   fd.Get("role_name").(string),
						"remote_addr": req.Connection.RemoteAddr,
					})
					return nil, nil
				},
			},
		},
	}
}
