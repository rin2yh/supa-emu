package store

import (
	"errors"
	"sync"
	"time"
)

type Store struct {
	mu sync.RWMutex

	users         map[string]*User
	emailIndex    map[string]string
	sessions      map[string]*Session
	refreshTokens map[string]*RefreshToken
	// parentToChild は rotation の親→子 token を O(1) で辿るための副索引。
	// 旧実装は ConsumeRefreshToken の reuse パスで全件走査だったため、長寿命プロセスで
	// O(N) スキャンがロック競合の原因になっていた。
	parentToChild map[string]string

	clock         func() time.Time
	reuseInterval time.Duration
}

type Config struct {
	Clock         func() time.Time
	ReuseInterval time.Duration
}

var (
	ErrUserAlreadyExists   = errors.New("store: user already exists")
	ErrUserNotFound        = errors.New("store: user not found")
	ErrInvalidRefreshToken = errors.New("store: invalid refresh token")
)

func New(cfg Config) *Store {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.ReuseInterval == 0 {
		cfg.ReuseInterval = 10 * time.Second
	}
	return &Store{
		users:         make(map[string]*User),
		emailIndex:    make(map[string]string),
		sessions:      make(map[string]*Session),
		refreshTokens: make(map[string]*RefreshToken),
		parentToChild: make(map[string]string),
		clock:         cfg.Clock,
		reuseInterval: cfg.ReuseInterval,
	}
}

func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = make(map[string]*User)
	s.emailIndex = make(map[string]string)
	s.sessions = make(map[string]*Session)
	s.refreshTokens = make(map[string]*RefreshToken)
	s.parentToChild = make(map[string]string)
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		Users:         []User{},
		Sessions:      []Session{},
		RefreshTokens: []RefreshToken{},
	}
	for _, u := range s.users {
		snap.Users = append(snap.Users, *s.cloneUser(u))
	}
	for _, sess := range s.sessions {
		snap.Sessions = append(snap.Sessions, *cloneSession(sess))
	}
	for _, rt := range s.refreshTokens {
		snap.RefreshTokens = append(snap.RefreshTokens, *cloneRefreshToken(rt))
	}
	return snap
}
