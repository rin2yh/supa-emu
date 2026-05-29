package config

// Supabase CLI が `supabase start` で発行する demo 値と一致させる。
// アプリ側の .dev.vars.example / supabase/config.toml と整合させるため変更しないこと。
const DefaultJWTSecret = "super-secret-jwt-token-with-at-least-32-characters-long"
