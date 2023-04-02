package cache

import (
	"crypto/sha256"
	"crypto/x509"
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
	timeoutInterval time.Duration
	evictTimer      *time.Timer
}

func hashCertificate(cert []byte) (string, error) {
	certificate, err := x509.ParseCertificate(cert)
	if err != nil {
		utils.PrintDebug("Not able to parse certificate")
		return "", err
	}

	res := fmt.Sprintf("%x", sha256.Sum256(certificate.Raw))
	return res, nil
}

func NewCache(timeoutInterval time.Duration, enabled bool) *Cache {
	cache := &Cache{
		items:           make(map[string]*Item),
		enabled:         enabled,
		timeoutInterval: timeoutInterval,
	}

	// periodically evict expired items from the cache
	cache.Evict()

	return cache
}

func (c *Cache) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

func (c *Cache) TimeoutDuration() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeoutInterval
}

func (c *Cache) Toggle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = !c.enabled
}

func (c *Cache) Evict() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.evictTimer != nil {
		c.evictTimer.Stop()
	}

	now := time.Now().Unix()
	for key, item := range c.items {
		if item.expiresAt < now {
			utils.PrintDebug("Deleting key: ", key)
			delete(c.items, key)
		}
	}

	c.evictTimer = time.AfterFunc(c.timeoutInterval, func() {
		go c.Evict()
	})
}

func (c *Cache) Add(cert []byte, value int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		// return gramine_ratls.CACHE_ERR_NOT_ENABLED
		return errors.New("not enabled")
	}

	h, err := hashCertificate(cert)
	if err != nil {
		return err
	}

	c.items[h] = &Item{
		key:       h,
		value:     value,
		expiresAt: time.Now().Add(c.timeoutInterval).Unix(),
	}

	return nil
}

func (c *Cache) AddItems(certs [][]byte) error {
	if !c.enabled {
		// return gramine_ratls.CACHE_ERR_NOT_ENABLED
		return errors.New("not enabled")
	}

	// optimistically add all successful certificates
	for _, cert := range certs {
		c.Add(cert, 0)
	}

	return nil
}

func (c *Cache) Read(cert []byte) (int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.enabled {
		// return gramine_ratls.CACHE_ERR_NOT_ENABLED
		return math.MinInt32, errors.New("not enabled")
	}

	h, err := hashCertificate(cert)
	if err != nil {
		return math.MinInt32, err
	}

	item, ok := c.items[h]
	if !ok {
		return math.MinInt32, errors.New("not found")
	}

	return item.value, nil
}
