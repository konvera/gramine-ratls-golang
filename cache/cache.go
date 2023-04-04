package cache

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/konvera/gramine-ratls-golang/utils"
)

type Item struct {
	key       string
	value     int
	expiresAt int64
}

type Cache struct {
	mu sync.RWMutex

	enabled         bool
	items           map[string]*Item
	queue           []Item
	timeoutInterval time.Duration
	cacheFailures   bool
}

func hashCertificate(cert []byte) string {
	res := fmt.Sprintf("%x", sha256.Sum256(cert))
	return res
}

// NewCache initialises the cache with required arguments
func NewCache(enabled bool, timeoutInterval time.Duration, cacheFailures bool) *Cache {
	queue := make([]Item, 0)

	cache := &Cache{
		items:           make(map[string]*Item),
		enabled:         enabled,
		timeoutInterval: timeoutInterval,
		queue:           queue,
		cacheFailures:   cacheFailures,
	}

	return cache
}

// IsEnabled returns whether the cache is enabled or not.
func (c *Cache) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// TimeoutDuration returns the duration after which value is evicted from cache.
func (c *Cache) TimeoutDuration() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeoutInterval
}

// IsFailuresCachingAllowed returns whether cache saves verification failures as well.
// Sucessful verification is referred as value `0`.
func (c *Cache) IsFailuresCachingAllowed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cacheFailures
}

// ToggleFailureCaching toggle fail results caching support
func (c *Cache) ToggleFailureCaching() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cacheFailures = !c.cacheFailures
}

// Toggle toggles cache support
func (c *Cache) Toggle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = !c.enabled
}

// evict removes redundant elements from the beginning of the queue which have surpassed their
// expiration duration.
func (c *Cache) evict() {
	if len(c.queue) == 0 {
		return
	}

	idx := 0
	now := time.Now().Unix()

	for _, item := range c.queue {
		if item.expiresAt > now {
			break
		}

		utils.PrintDebug("deleting key: ", item.key)
		delete(c.items, item.key)
		idx++
	}

	c.queue = c.queue[idx:]
}

// Add adds new item to the cache. New item is added at the back of the queue and if capacity is full,
// an item from the beginning, i.e. the oldest item is removed from the cache.
func (c *Cache) Add(cert []byte, value int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		utils.PrintDebug("cache not enabled")
		return errors.New("not enabled")
	}

	// remove redundant items
	c.evict()

	if value != 0 && !c.cacheFailures {
		utils.PrintDebug("caching of failed values not allowed")
		return errors.New("failed valued not allowed")
	}

	h := hashCertificate(cert)

	if _, ok := c.items[h]; ok {
		utils.PrintDebug("key already exists in cache: ", h)
		return nil
	}

	item := Item{
		key:       h,
		value:     value,
		expiresAt: time.Now().Add(c.timeoutInterval).Unix(),
	}

	c.queue = append(c.queue, item)
	c.items[h] = &item

	return nil
}

// AddItems add multiple items to the cache. It can be used to initialise the cache with some
// successful attestations.
func (c *Cache) AddItems(certs [][]byte) error {
	if !c.enabled {
		return errors.New("cache not enabled")
	}

	// optimistically add all successful certificates
	for _, cert := range certs {
		c.Add(cert, 0)
	}

	return nil
}

// Read reads an items's value from the cache and removes any redundant item at the start.
func (c *Cache) Read(cert []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return math.MinInt32, errors.New("cache not enabled")
	}

	// remove redundant items
	c.evict()

	h := hashCertificate(cert)
	item, ok := c.items[h]
	if !ok {
		return math.MinInt32, errors.New("not found")
	}

	return item.value, nil
}
