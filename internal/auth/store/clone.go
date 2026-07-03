package store

import "sort"

// cloneUser は呼び出し側の map/スライス書き換えがストア本体に漏れないよう deep copy する。
// 旧シャローコピー実装では `clone.AppMetadata["k"]=v` が RWMutex 外からストアの map を
// 直接書き換え、Snapshot 中の goroutine と並走して concurrent map fatal を起こすリスクがあった。
func (s *Store) cloneUser(u *User) *User {
	c := *u
	c.AppMetadata = cloneAnyMap(u.AppMetadata)
	c.UserMetadata = cloneAnyMap(u.UserMetadata)
	if u.Identities != nil {
		c.Identities = make([]Identity, len(u.Identities))
		for i, id := range u.Identities {
			ic := id
			ic.IdentityData = cloneAnyMap(id.IdentityData)
			c.Identities[i] = ic
		}
	}
	if u.PasswordHash != nil {
		c.PasswordHash = append([]byte(nil), u.PasswordHash...)
	}
	// The factors map is the single source of truth; derive and fill the user's
	// factors here, ordered by CreatedAt.
	c.Factors = s.userFactorsLocked(u.ID)
	return &c
}

// userFactorsLocked clones the user's factors ordered by CreatedAt (ties broken
// by ID). It assumes either the read or write lock is held. It returns a non-nil
// empty slice even with no factors, so supabase-js's user.factors is never null.
func (s *Store) userFactorsLocked(userID string) []Factor {
	out := make([]Factor, 0)
	for _, f := range s.factors {
		if f.UserID == userID {
			out = append(out, *cloneFactor(f))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func cloneSession(sess *Session) *Session {
	c := *sess
	if sess.AMR != nil {
		c.AMR = append([]AMREntry(nil), sess.AMR...)
	}
	return &c
}

func cloneFactor(f *Factor) *Factor {
	c := *f
	return &c
}

func cloneRefreshToken(rt *RefreshToken) *RefreshToken {
	c := *rt
	return &c
}

func cloneAnyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = cloneAny(v)
	}
	return cp
}

// cloneAny は any 値を深くコピーする。slice / map / nested any を再帰的に複製し、
// それ以外の値（string / bool / 数値）は値コピーで十分。
// CreateUser が AppMetadata["providers"] に []string を入れている等、ネストした参照型を
// 含むケースで Store と clone を確実に切り離すため。
func cloneAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneAnyMap(x)
	case []any:
		cp := make([]any, len(x))
		for i, e := range x {
			cp[i] = cloneAny(e)
		}
		return cp
	case []string:
		cp := make([]string, len(x))
		copy(cp, x)
		return cp
	case []byte:
		return append([]byte(nil), x...)
	default:
		return v
	}
}
