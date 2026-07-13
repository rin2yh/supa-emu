package store

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrIdentityExists is returned when an identity for the same provider is
	// already attached to the user.
	ErrIdentityExists = errors.New("store: identity already exists")
	// ErrIdentityNotFound is returned when no identity with the given id belongs
	// to the user.
	ErrIdentityNotFound = errors.New("store: identity not found")
	// ErrLastIdentity is returned when unlinking would leave the user with no
	// identities. GoTrue forbids removing the final identity.
	ErrLastIdentity = errors.New("store: cannot unlink the last identity")
)

// newIdentity builds a provider identity, stamping the row id (identity_id), the
// three matching timestamps, and defaulting a nil data map. It is the single
// place the Identity shape is assembled, shared by CreateUser (email identity),
// AddIdentity (seed), and appendProviderIdentityLocked (OAuth) so a new field is
// added once. Callers own the returned struct's data map; it is not cloned here.
func newIdentity(userID, provider, providerID string, data map[string]any, now time.Time) Identity {
	if data == nil {
		data = map[string]any{}
	}
	return Identity{
		IdentityID:   uuid.NewString(),
		ID:           providerID,
		UserID:       userID,
		Provider:     provider,
		IdentityData: data,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastSignInAt: now,
	}
}

// AddIdentity attaches a new provider identity to an existing user and returns
// the updated user clone. A second identity for the same provider yields
// ErrIdentityExists; a missing user yields ErrUserNotFound. The identity_data is
// cloned, and the user's app_metadata providers are recomputed from the full
// identity set so getUserIdentities / linked:true stay consistent.
func (s *Store) AddIdentity(userID, provider string, identityData map[string]any) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return nil, ErrUserNotFound
	}
	if hasProviderLocked(u, provider) {
		return nil, ErrIdentityExists
	}
	now := s.clock()
	data := cloneAnyMap(identityData)
	if data == nil {
		data = map[string]any{}
	}
	// The provider-scoped id (json:"id", the sub) defaults to identity_data["sub"]
	// when present, else the user id — matching how the email identity is seeded.
	providerID, _ := data["sub"].(string)
	if providerID == "" {
		providerID = userID
		data["sub"] = providerID
	}
	u.Identities = append(u.Identities, newIdentity(userID, provider, providerID, data, now))
	recomputeProvidersLocked(u)
	u.UpdatedAt = now
	return s.cloneUser(u), nil
}

// RemoveIdentity unlinks the identity with the given identity_id from the user
// and returns the updated user clone. It refuses to remove the user's only
// identity (ErrLastIdentity) and reports ErrIdentityNotFound / ErrUserNotFound
// otherwise. The app_metadata providers are recomputed after removal.
func (s *Store) RemoveIdentity(userID, identityID string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return nil, ErrUserNotFound
	}
	idx := -1
	for i, id := range u.Identities {
		if id.IdentityID == identityID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, ErrIdentityNotFound
	}
	if len(u.Identities) == 1 {
		return nil, ErrLastIdentity
	}
	u.Identities = append(u.Identities[:idx], u.Identities[idx+1:]...)
	recomputeProvidersLocked(u)
	u.UpdatedAt = s.clock()
	return s.cloneUser(u), nil
}

// recomputeProvidersLocked rebuilds app_metadata.provider / providers from the
// user's current identity set. provider tracks the primary (first) identity;
// providers lists every attached provider. It assumes the write lock is held.
func recomputeProvidersLocked(u *User) {
	if u.AppMetadata == nil {
		u.AppMetadata = map[string]any{}
	}
	providers := make([]string, 0, len(u.Identities))
	for _, id := range u.Identities {
		providers = append(providers, id.Provider)
	}
	u.AppMetadata["providers"] = providers
	if len(providers) > 0 {
		u.AppMetadata["provider"] = providers[0]
	}
}
