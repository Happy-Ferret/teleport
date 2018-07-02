/*
Copyright 2016 Gravitational, Inc.

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

package dir

import (
	"fmt"
	//"sync/atomic"
	"testing"
	"time"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/test"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"

	"gopkg.in/check.v1"
)

type Suite struct {
	dirName string
	bk      backend.Backend
	clock   clockwork.FakeClock
	suite   test.BackendSuite
}

var _ = trace.AccessDenied
var _ = check.Suite(&Suite{clock: clockwork.NewFakeClock()})

// bootstrap check.v1:
func TestFSBackend(t *testing.T) { check.TestingT(t) }

func (s *Suite) SetUpSuite(c *check.C) {
	var err error

	dirName := c.MkDir()
	s.bk, err = New(backend.Params{"path": dirName})
	fmt.Printf("--> dirName: %v\n", dirName)

	sb, ok := s.bk.(*backend.Sanitizer)
	c.Assert(ok, check.Equals, true)
	sb.Backend().(*Backend).InternalClock = s.clock

	c.Assert(err, check.IsNil)

	// backend must create the dir:
	c.Assert(utils.IsDir(dirName), check.Equals, true)

	s.suite.B = s.bk
}

/*
func (s *Suite) TestBasic(c *check.C) {
	err := s.bk.UpsertVal([]string{"roles", "admin"}, "params", []byte("foo"), backend.Forever)
	c.Assert(err, check.IsNil)
	err = s.bk.UpsertVal([]string{"namespaces", "default", "nodes"}, "123", []byte("bar"), backend.Forever)
	c.Assert(err, check.IsNil)

	items, err := s.bk.GetItems([]string{"roles"})
	c.Assert(err, check.IsNil)
	fmt.Printf("--> items: %v.\n", items)

	items, err = s.bk.GetItems([]string{"namespaces", "default", "nodes"})
	c.Assert(err, check.IsNil)
	fmt.Printf("--> items: %v.\n", items)

	time.Sleep(60 * time.Second)
}
*/

/*
func (s *Suite) BenchmarkOperations(c *check.C) {
	bucket := []string{"bench", "bucket"}
	keys := []string{"key1", "key2", "key3", "key4", "key5"}
	value1 := "some backend value, not large enough, but not small enought"
	for i := 0; i < c.N; i++ {
		for _, key := range keys {
			err := s.bk.UpsertVal(bucket, key, []byte(value1), time.Hour)
			c.Assert(err, check.IsNil)
			bytes, err := s.bk.GetVal(bucket, key)
			c.Assert(err, check.IsNil)
			c.Assert(string(bytes), check.Equals, value1)
			err = s.bk.DeleteKey(bucket, key)
			c.Assert(err, check.IsNil)
		}
	}
}
*/

func (s *Suite) TestConcurrentOperations(c *check.C) {
	bucket := []string{"concurrent", "bucket"}

	value1 := "this first value should not be corrupted by concurrent ops"
	value2 := "this second value should not be corrupted too"
	const attempts = 50
	resultsC := make(chan struct{}, attempts*4)
	for i := 0; i < attempts; i++ {
		go func(cnt int) {
			err := s.bk.UpsertVal(bucket, "key", []byte(value1), time.Hour)
			resultsC <- struct{}{}
			c.Assert(err, check.IsNil)
		}(i)

		go func(cnt int) {
			err := s.bk.CompareAndSwapVal(bucket, "key", []byte(value2), []byte(value1), time.Hour)
			resultsC <- struct{}{}
			if err != nil && !trace.IsCompareFailed(err) {
				c.Assert(err, check.IsNil)
			}
		}(i)

		go func(cnt int) {
			err := s.bk.CreateVal(bucket, "key", []byte(value2), time.Hour)
			resultsC <- struct{}{}
			if err != nil && !trace.IsAlreadyExists(err) {
				c.Assert(err, check.IsNil)
			}
		}(i)

		go func(cnt int) {
			bytes, err := s.bk.GetVal(bucket, "key")
			resultsC <- struct{}{}
			if err != nil && !trace.IsNotFound(err) {
				c.Assert(err, check.IsNil)
			}
			// make sure data is not corrupted along the way
			if err == nil {
				val := string(bytes)
				if val != value1 && val != value2 {
					c.Fatalf("expected one of %q or %q and got %q", value1, value2, val)
				}
			}
		}(i)

		go func(cnt int) {
			err := s.bk.DeleteBucket([]string{"concurrent"}, "bucket")
			if err != nil && !trace.IsNotFound(err) {
				c.Assert(err, check.IsNil)
			}
			resultsC <- struct{}{}
		}(i)
	}
	timeoutC := time.After(3 * time.Second)
	for i := 0; i < attempts*5; i++ {
		select {
		case <-resultsC:
		case <-timeoutC:
			c.Fatalf("timeout waiting for goroutines to finish")
		}
	}
}

func (s *Suite) TestCRUD(c *check.C) {
	s.suite.BasicCRUD(c)
}

/*
func (s *Suite) TestCompareAndSwap(c *check.C) {
	s.suite.CompareAndSwap(c)
}

func (s *Suite) TestCreateAndRead(c *check.C) {
	bucket := []string{"one", "two"}

	// must succeed:
	err := s.bk.CreateVal(bucket, "key", []byte("original"), backend.Forever)
	c.Assert(err, check.IsNil)

	// must get 'already exists' error
	err = s.bk.CreateVal(bucket, "key", []byte("failed-write"), backend.Forever)
	c.Assert(trace.IsAlreadyExists(err), check.Equals, true)

	// read back the original:
	val, err := s.bk.GetVal(bucket, "key")
	c.Assert(err, check.IsNil)
	c.Assert(string(val), check.Equals, "original")

	// upsert:
	err = s.bk.UpsertVal(bucket, "key", []byte("new-value"), backend.Forever)
	c.Assert(err, check.IsNil)

	// read back the new value:
	val, err = s.bk.GetVal(bucket, "key")
	c.Assert(err, check.IsNil)
	c.Assert(string(val), check.Equals, "new-value")

	// read back non-existing (bad path):
	val, err = s.bk.GetVal([]string{"bad", "path"}, "key")
	c.Assert(err, check.NotNil)
	c.Assert(val, check.IsNil)
	c.Assert(trace.IsNotFound(err), check.Equals, true)

	// read back non-existing (bad key):
	val, err = s.bk.GetVal(bucket, "bad-key")
	c.Assert(err, check.NotNil)
	c.Assert(val, check.IsNil)
	c.Assert(trace.IsNotFound(err), check.Equals, true)
}

func (s *Suite) TestListDelete(c *check.C) {
	root := []string{"root"}
	kid := []string{"root", "kid"}

	// list from non-existing bucket (must return an empty array)
	kids, err := s.bk.GetKeys([]string{"bad", "bucket"})
	c.Assert(err, check.IsNil)
	c.Assert(kids, check.HasLen, 0)

	// create two entries in root:
	s.bk.CreateVal(root, "one", []byte("1"), backend.Forever)
	s.bk.CreateVal(root, "two", []byte("2"), time.Second)

	// create one entry in the kid:
	s.bk.CreateVal(kid, "three", []byte("3"), backend.Forever)

	// list the root (should get 2 back):
	kids, err = s.bk.GetKeys(root)
	c.Assert(err, check.IsNil)
	c.Assert(kids, check.DeepEquals, []string{"kid", "one", "two"})

	// list the kid (should get 1)
	kids, err = s.bk.GetKeys(kid)
	c.Assert(err, check.IsNil)
	c.Assert(kids, check.HasLen, 1)
	c.Assert(kids[0], check.Equals, "three")

	// delete one of the kids:
	err = s.bk.DeleteKey(kid, "three")
	c.Assert(err, check.IsNil)
	kids, err = s.bk.GetKeys(kid)
	c.Assert(kids, check.HasLen, 0)

	// try to delete non-existing key:
	err = s.bk.DeleteKey(kid, "three")
	c.Assert(trace.IsNotFound(err), check.Equals, true)

	// try to delete the root bucket:
	err = s.bk.DeleteBucket(root, "kid")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestTTL(c *check.C) {
	bucket := []string{"root"}
	value := []byte("value")

	s.bk.CreateVal(bucket, "key", value, time.Second)
	v, err := s.bk.GetVal(bucket, "key")
	c.Assert(err, check.IsNil)
	c.Assert(string(v), check.Equals, string(value))

	// after sleeping for 2 seconds the value must be gone:
	s.clock.Advance(time.Second * 2)

	v, err = s.bk.GetVal(bucket, "key")
	c.Assert(trace.IsNotFound(err), check.Equals, true)
	c.Assert(err.Error(), check.Equals, `key "key" is not found`)
	c.Assert(v, check.IsNil)
}

func (s *Suite) TestLocking(c *check.C) {
	lock := "test_lock"
	ttl := time.Second * 10

	// acquire a lock, wait for TTL to expire, acquire again and succeed:
	c.Assert(s.bk.AcquireLock(lock, ttl), check.IsNil)
	s.clock.Advance(ttl + 1)
	c.Assert(s.bk.AcquireLock(lock, ttl), check.IsNil)
	c.Assert(s.bk.ReleaseLock(lock), check.IsNil)

	// lets make sure locking actually works:
	c.Assert(s.bk.AcquireLock(lock, ttl), check.IsNil)
	i := int32(0)
	go func() {
		c.Assert(s.bk.AcquireLock(lock, ttl), check.IsNil)
		atomic.AddInt32(&i, 1)
	}()
	time.Sleep(time.Millisecond * 2)
	// make sure i did not change (the modifying gorouting was locked)
	c.Assert(atomic.LoadInt32(&i), check.Equals, int32(0))
	s.clock.Advance(ttl + 1)

	// release the lock, and the gorouting should unlock and advance i
	s.bk.ReleaseLock(lock)
	resumed := false
	for attempt := 0; attempt < 100 && !resumed; attempt++ {
		time.Sleep(time.Millisecond * 10)
		resumed = atomic.LoadInt32(&i) > 0
	}
	c.Assert(resumed, check.Equals, true)

}
*/
