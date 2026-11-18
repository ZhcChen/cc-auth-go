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

// 数字映射（BIGINT 主键的存储使用）也须在参考实现上通过，以验证映射保持顺序与唯一。
func TestStoreNumericIDs(t *testing.T) {
	storetest.RunWith(t, func(*testing.T) auth.Store { return memstore.New() }, storetest.Numeric())
}
