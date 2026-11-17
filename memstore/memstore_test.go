package memstore_test

import (
	"testing"

	auth "github.com/ZhcChen/cc-auth-go"
	"github.com/ZhcChen/cc-auth-go/memstore"
	"github.com/ZhcChen/cc-auth-go/storetest"
)

func TestStore(t *testing.T) {
	storetest.Run(t, func(*testing.T) auth.Store { return memstore.New() })
}
