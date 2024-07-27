/*
Copyright 2024 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package git

import (
	"context"
	"fmt"
	"time"

	"github.com/fluxcd/pkg/auth/azure"
	pkgAuth "github.com/fluxcd/pkg/auth/git"
	"github.com/fluxcd/pkg/cache"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

const (
	// We want to cache authentication credentials to git repositories for
	// providers (example: azure)
	DefaultAuthCacheCapacity = 10
	// The cache cleanup interval, to remove expired entries
	// 1 minute is a reasonable interval for authentication tokens.
	// We don't want to be aggressive with the cleanup, as the tokens
	// are valid for a longer period of time usually.
	defaultAuthCacheInterval = time.Minute
)

// ProviderAuth contains the provider credentials and auth options
// for the provider. The auth options has a cache to avoid getting credentials
// for the same repository URL
type ProviderAuth struct {
	Credentials *pkgAuth.Credentials
	Options     *pkgAuth.AuthOptions
}

// ProviderAuthCacheOptionFunc is a functional option for the ProviderAuthCache
type ProviderAuthCacheOptionFunc func(opts *providerAuthCacheOptions)

type providerAuthCacheOptions struct {
	capacity int
}

// WithCacheCapacity sets the capacity of the cache.
func WithCacheCapacity(capacity int) ProviderAuthCacheOptionFunc {
	return func(opts *providerAuthCacheOptions) {
		opts.capacity = capacity
	}
}

type ProviderAuthenticator struct {
	cache cache.Expirable[cache.StoreObject[pkgAuth.Credentials]]
}

// NewProviderAuthCache returns a new ProviderAuthCache.
// The capacity is the number of authenticators to cache.
// If the capacity is less than or equal to 0, the cache is disabled.
func NewProviderAuthenticator(opts ...ProviderAuthCacheOptionFunc) (*ProviderAuthenticator, error) {
	o := &providerAuthCacheOptions{}
	for _, opt := range opts {
		opt(o)
	}

	var (
		c   cache.Expirable[cache.StoreObject[pkgAuth.Credentials]]
		err error
	)
	if o.capacity > 0 {
		c, err = cache.New(o.capacity, cache.StoreObjectKeyFunc,
			cache.WithCleanupInterval[cache.StoreObject[pkgAuth.Credentials]](defaultAuthCacheInterval))
		if err != nil {
			return nil, fmt.Errorf("failed to create cache: %w", err)
		}
	}

	return &ProviderAuthenticator{cache: c}, nil
}

func (p *ProviderAuthenticator) Authorization(ctx context.Context, url, provider string) (*ProviderAuth, error) {
	var (
		providerCreds *pkgAuth.Credentials
		authOpts      *pkgAuth.AuthOptions
		err           error
	)
	switch provider {
	case sourcev1.AzureAuthProvider:
		authOpts = &pkgAuth.AuthOptions{}
		authOpts.ProviderOptions = pkgAuth.ProviderOptions{
			AzureOpts: []azure.ProviderOptFunc{
				azure.WithAzureDevOpsScope(),
			},
		}
		authOpts.Cache = p.cache
		providerCreds, err = pkgAuth.GetCredentials(ctx, url, provider, authOpts)
		if err != nil {
			return nil, err
		}
	// Add other providers here
	default:
		return nil, nil
	}

	return &ProviderAuth{Credentials: providerCreds, Options: authOpts}, nil
}
