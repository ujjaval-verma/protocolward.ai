// SPDX-License-Identifier: Apache-2.0

package upstream

import "time"

// DefaultMaxConns is the production pool size, for assertions.
const DefaultMaxConns = defaultMaxConns

// NewWithPool is New with a test-sized pool and idle timeout.
func NewWithPool(cfg Config, maxConns int, idle time.Duration) (*Client, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return newClient(c.cfg, maxConns, idle), nil
}

// SetAfterSlotHook sets a function that Query calls once, right after a slot
// is acquired and before the post-slot re-check. Set it before the first
// Query and never change it afterwards.
func SetAfterSlotHook(c *Client, f func()) { c.afterSlot = f }

// SetAfterReadHook sets a function that exchange calls after every read,
// before it stops the ctx's cancel callback. Set it before the first Query
// and never change it afterwards.
func SetAfterReadHook(c *Client, f func()) { c.afterRead = f }

// SetAfterFreeHook sets a function that Query calls right after it releases
// its slot. Set it before the first Query and never change it afterwards.
func SetAfterFreeHook(c *Client, f func()) { c.afterFree = f }

// IdleLen returns the number of connections on the idle stack.
func IdleLen(c *Client) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.idle)
}
