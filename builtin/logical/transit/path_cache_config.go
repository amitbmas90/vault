package transit

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/keysutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) pathCacheConfig() *framework.Path {
	return &framework.Path{
		Pattern: "cache-config",
		Fields: map[string]*framework.FieldSchema{
			"cache-type": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
				Description: `
Type of cache to use. Currently "unlimited" and "lru" are supported.
`,
			},

			"cache-size": &framework.FieldSchema{
				Type: framework.TypeInt,
				Description: `
Size of cache for a cache type that accepts a size. This is required for cache types
that accept a size and currently applies only to the "lru" cache type.
`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:    b.pathCacheConfigRead,
				Summary:     "Returns the type and size of the active cache",
				Description: "",
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.pathCacheConfigWrite,
				Summary:     "Configures a new cache of the specified type and size",
				Description: "",
			},

			logical.CreateOperation: &framework.PathOperation{
				Callback:    b.pathCacheConfigWrite,
				Summary:     "Configures a new cache of the specified type and size",
				Description: "",
			},
		},

		HelpSynopsis:    pathCacheConfigHelpSyn,
		HelpDescription: pathCacheConfigHelpDesc,
	}
}

func (b *backend) pathCacheConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// get target cacheType
	cacheTypeStr := d.Get("cache-type").(string)
	cacheSize := d.Get("cache-size").(int)
	var cacheType keysutil.CacheType
	switch cacheTypeStr {
	case "unlimited":
		cacheType = keysutil.SyncMap
	case "lru":
		cacheType = keysutil.LRU
	default:
		cacheType = keysutil.NotImplemented
	}

	// err if the requested cacheType has not been implemented
	if cacheType == keysutil.NotImplemented {
		return logical.ErrorResponse(fmt.Sprintf("unknown cache-type %q", cacheTypeStr)), logical.ErrInvalidRequest
	}

	// err if cacheType is lru but no cache-size was specified
	if cacheType == keysutil.LRU && cacheSize <= 0 {
		return logical.ErrorResponse("for lru cache-type, cache-size must be specified and be greater than zero"), logical.ErrInvalidRequest
	}

	// convert the cache if the specified type and size are different from the current cache type and size
	if cacheType == b.lm.GetCacheType() && cacheSize == b.lm.GetCacheSize() {
		return nil, nil
	}

	if cacheType == keysutil.SyncMap {
		b.lm.ConvertCacheToSyncmap()
	}

	if cacheType == keysutil.LRU {
		err := b.lm.ConvertCacheToLRU(cacheSize)
		if err != nil {
			return nil, errwrap.Wrapf("failed to convert cache-type to lru: {{err}}", err)
		}
	}

	// store cache type
	entry, err := logical.StorageEntryJSON("config/cache-type", &configCacheType{
		CacheType: cacheType,
		Size:      cacheSize,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type configCacheType struct {
	CacheType keysutil.CacheType `json:"cacheType"`
	Size      int                `json:"size"`
}

func (b *backend) pathCacheConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var cacheType string
	switch b.lm.GetCacheType() {
	case keysutil.SyncMap:
		cacheType = "unlimited"
	case keysutil.LRU:
		cacheType = "lru"
	default:
		cacheType = "unknown"
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"cache_type":     cacheType,
			"cache_max_size": b.lm.GetCacheSize(),
		},
	}

	return resp, nil
}

const pathCacheConfigHelpSyn = `Configure caching strategy`

const pathCacheConfigHelpDesc = `
This path is used to configure and query the caching strategy for the transit mount.
For cache-types that do not have a maximum size (like "unlimited") a 0 cache-max-size is returned.
`
