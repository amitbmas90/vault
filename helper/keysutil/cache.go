package keysutil

type CacheType int

const (
	NotInitialized CacheType = iota
	NotImplemented
	SyncMap
	LRU
)

type Cache interface {
	Delete(key interface{})
	Load(key interface{}) (value interface{}, ok bool)
	Store(key, value interface{})
	Size() int
}
